## Оглавление

- [Подробные исправления](#sec-1-podrobnye-ispravleniya)
    - [1. Нет проверки авторизации в endpoint-ах](#1-net-proverki-avtorizacii-v-endpoint-ah)
    - [2. Повышение привилегий и mass assignment в `saveData()`](#2-povyshenie-privilegij-i-mass-assignment-v-savedata)
    - [3. Пароли: обратимый AES → `password_hash` / `password_verify`](#3-paroli-obratimyj-aes-password-hash-password-verify)
    - [4. Секреты в коде](#4-sekrety-v-kode)
    - [5. CSRF, выход, сессии, cookie, перебор пароля](#5-csrf-vyhod-sessii-cookie-perebor-parolya)
    - [6. Stored XSS и DOM XSS](#6-stored-xss-i-dom-xss)
    - [7. Загрузка файлов и каталог `/img`](#7-zagruzka-fajlov-i-katalog-img)
    - [8. Утечка колонки «Контакт собственника»](#8-utechka-kolonki-kontakt-sobstvennika)
    - [9. `set_id.php` и `AUTO_INCREMENT`](#9-set-id-php-i-auto-increment)
    - [10. Серверная валидация](#10-servernaya-validaciya)
    - [11. Короткие теги `<?`](#11-korotkie-tegi)
- [Сводная таблица всех найденных проблем](#svodnaya-tablica-vseh-najdennyh-problem)

# Аудит безопасности - защита серверной логики и данных, этап 2

На втором этапе устранены уязвимости, связанные не только с SQL-инъекциями, но и с контролем доступа, обработкой пользовательских данных и безопасностью серверной логики. Основной акцент сделан на том, чтобы критические правила безопасности проверялись на сервере и не могли быть обойдены прямыми HTTP-запросами.

В рамках этапа усилены авторизация и разграничение прав, устранена возможность повышения привилегий и mass assignment, пароли переведены с обратимого AES на `password_hash` / `password_verify`, секреты вынесены из исходного кода. Также добавлены CSRF-защита, безопасное управление сессиями и cookie, защита от перебора паролей, исправлены Stored/DOM XSS, усилена безопасность загрузки файлов и каталога `/img`, закрыта утечка контактов собственников, удалено небезопасное изменение `AUTO_INCREMENT` и добавлена серверная валидация данных.

Дополнительно выполнены сопутствующие hardening-исправления: security headers, безопасная генерация случайных паролей, защита cookie, отказ от коротких PHP-тегов и закрытие прямого доступа к служебным шаблонам.

[🔝 Наверх](#оглавление)
<a id="sec-1-podrobnye-ispravleniya"></a>
## Подробные исправления

[🔝 Наверх](#оглавление)
<a id="1-net-proverki-avtorizacii-v-endpoint-ah"></a>
### 1. Нет проверки авторизации в endpoint-ах

**Причина.** Вход проверялся только в `index.php`. Остальные файлы вызывались напрямую и отдавали данные или принимали запись без сессии. Файлы `admin/parts/*.php` тоже были открыты и работали без `session_start()`.

**Решение.** Одна точка проверки `require_auth($allowedPerms = null)` в `functions.admin.php`. Она вызывается сразу после `db_connect()` в каждом эндпоинте. Ответы: `401` без входа, `403` без нужной роли. Сессия сверяется с БД (`is_logged_in()`), а право на таблицу проверяется в конструкторе `ObjectTable`.

**Оригинал (`jqgrid.show.php`):**
```php
db_connect();

$tblName = $_GET["tblName"] ?? "";
$table = new ObjectTable($tblName);

echo $table->showData();
```

**Исправлено:**
```php
db_connect();

// [SEC-1] чтение данных - только для вошедших пользователей (раньше было доступно анониму)
require_auth();

$tblName = $_GET["tblName"] ?? "";
$table = new ObjectTable($tblName); // белый список + [SEC-1] право чтения таблицы в конструкторе
echo $table->showData();
```

То же `require_auth();` добавлено в `jqgrid.table.php`, `select.get.php`. В `jqgrid.edit.php`, `set_id.php`, `onlymy.php`, `file.upload.php` — `require_auth(); csrf_check();`.

**Оригинал (`functions.admin.php`, конструктор):**
```php
$this->dbName = $tableName;
$this->colArray = $this->getTableColArray();
```
**Исправлено:**
```php
// [SEC-1] Таблица доступна на чтение не всем: без права чтения объект не создаётся вовсе
if (!self::canAccess($tableName, "read")) {
    http_response_code(403);
    exit("Forbidden");
}
$this->dbName = $tableName;
```

**Матрица прав (новая):**
```php
const READ_PERMISSIONS  = ["NL_VIEW"=>[2], "NL_HOUSES"=>[2], "NL_MATERIAL"=>[2], "NL_USER"=>[2], "NL_PROP_RESALE"=>[1,2,3]];
const WRITE_PERMISSIONS = ["NL_VIEW"=>[2], "NL_HOUSES"=>[2], "NL_MATERIAL"=>[2], "NL_USER"=>[2], "NL_PROP_RESALE"=>[1,2]];
```
Справочники и пользователи доступны только администратору. Это совпадает с прежним UI: вкладка «Справочники» показывалась только `ID_NL_USER_PERMISSION == 2`. Но на сервере это не проверялось. Журнал читают все, пишут пользователь (1) и администратор (2); гость (3) только читает. Это поведение прежнего `saveData()`.

**Части админки (`admin/parts/*.php`).** В начале каждого файла guard: если функции не загружены (прямой вызов), подключаются конфиг и функции и вызывается `db_connect()`; затем `require_auth()`. Для `dicts.php` это `require_auth(array(2))`. В `includeAdminPartsByLvl()` добавлено условие: `/admin/dicts` без прав администратора показывает главную. `login.php` остаётся доступным анониму, но получает сессию для CSRF-токена.

```php
// functions.admin.php, includeAdminPartsByLvl()
$dictsDenied = ($page === "dicts") && ((int)($_SESSION["ID_NL_USER_PERMISSION"] ?? 0) !== 2);
if (preg_match('/^[A-Za-z0-9_-]+$/', $page) && file_exists($main_file) && !$dictsDenied) {
```

**Что решает.** Анонимный доступ ко всем эндпоинтам и частям админки закрыт. Прежнее поведение ролей сохранено. Дополнительно `is_logged_in()` на каждом запросе проверяет, что пользователь ещё существует, обновляет его права из БД (разжалованный администратор теряет их сразу) и выходит по таймауту простоя 2 часа.

---

[🔝 Наверх](#оглавление)
<a id="2-povyshenie-privilegij-i-mass-assignment-v-savedata"></a>
### 2. Повышение привилегий и mass assignment в `saveData()`

**Причина.**
1. Права на таблицу не проверялись: пользователь `1` мог вызвать `edit/add` для `NL_USER`.
2. Проверка владельца `row_cur["ID_NL_USER"] != $_SESSION["ID_NL_USER"]` для `NL_USER` сравнивала строку пользователя с самим собой: `ID_NL_USER` — это его же первичный ключ. Он мог править себя и поставить `ID_NL_USER_PERMISSION = 2`.
3. Поле `ID_NL_USER` в журнале принималось из формы (владелец записи подменялся).
4. Не было проверки, что запись существует, и защиты строк администраторов (они скрыты в гриде фильтром `!= 2`, но прямым POST правились).

**Оригинал:**
```php
if ($oper != "add") {
    ...
    if (($_SESSION["ID_NL_USER_PERMISSION"] ?? 0) == "3") {
        die();
    } elseif ((($_SESSION["ID_NL_USER_PERMISSION"] ?? 0) == "1") && (($row_cur["ID_NL_USER"] ?? null) != ($_SESSION["ID_NL_USER"] ?? null))) {
        die();
    }
}
```

**Исправлено:**
```php
// [SEC-2] Право записи в таблицу проверяется на сервере
if (!self::canAccess($this->dbName, "write")) { http_response_code(403); die("Forbidden"); }
$perm = (int)($_SESSION["ID_NL_USER_PERMISSION"] ?? 0);
$myId = (int)($_SESSION["ID_NL_USER"] ?? 0);
$ownerCol = $this->getOwnerColumn(); // "ID_NL_USER" только у журналов, у NL_USER - null

if ($oper != "add") {
    ...
    if (!is_array($row_cur)) { http_response_code(404); die("Not found"); }
    if ($perm == 3) { die(); }
    // владелец - по колонке-владельцу таблицы, а не "запись сама с собой"
    if (($perm != 2) && ($ownerCol !== null) && ((int)$row_cur[$ownerCol] !== $myId)) {
        http_response_code(403); die("Forbidden");
    }
    // строки администраторов скрыты в гриде - прямым POST менять/удалять их тоже нельзя
    if (($this->dbName == "NL_USER") && ((int)$row_cur["ID_NL_USER_PERMISSION"] === 2)) {
        http_response_code(403); die("Forbidden");
    }
}

// Mass assignment: ответственного для не-администратора назначает СЕРВЕР
if (($ownerCol !== null) && ($oper != "del") && ($perm != 2)) {
    $post[$ownerCol] = ($oper == "add") ? (string)$myId : (string)$row_cur[$ownerCol];
}
```

`getOwnerColumn()` возвращает `ID_NL_USER` только если у таблицы есть колонка-владелец и это не `NL_USER`:
```php
public function getOwnerColumn() {
    return (($this->dbName !== "NL_USER") && isset($this->colArray["ID_NL_USER"])) ? "ID_NL_USER" : null;
}
```

**Права на поля.** Обычный пользователь больше не может записать значение в `ID_NL_USER`. `ID_NL_USER_PERMISSION` вообще недоступно обычному пользователю: у него нет права записи в `NL_USER`. Для администратора значения select проверяются: должны существовать в справочнике (см. пункт 10).

**Что решает.** Нельзя повысить права, поменять владельца записи, править чужие записи и строки администраторов. Для ранее «пустых» `edit/del` по несуществующему id теперь `404`.

---

[🔝 Наверх](#оглавление)
<a id="3-paroli-obratimyj-aes-password-hash-password-verify"></a>
### 3. Пароли: обратимый AES → `password_hash` / `password_verify`

**Причина.** `AES_ENCRYPT` обратим если есть ключ. Метод `getData` расшифровывал пароли и отдавал их в грид.

**Оригинал (запись):**
```php
case "encrypted":
    return array("AES_ENCRYPT(?, ?)", array($raw, AESKEY));
```
**Исправлено:**
```php
case "encrypted":
    // [SEC-3] необратимый хеш (bcrypt) вместо AES_ENCRYPT с ключом из исходников
    return array("?", array(password_hash($raw, PASSWORD_DEFAULT)));
```

**Оригинал (чтение, `getData`):**
```php
$query = "SELECT *";
for (...) {
    if ($col->type == "encrypted") {
        $query .= ", AES_DECRYPT(tbl." . db_ident($col->dbName) . ", ?) AS " . db_ident($col->dbName . "_DECRYPTED");
        $params[] = AESKEY;
    }
}
...
} elseif ($col->type == "encrypted") { ; $rowName .= "_DECRYPTED"; }
array_push($data[$i], $row[$rowName]);
```
**Исправлено:** выборка `AES_DECRYPT` удалена, а в выводе:
```php
$value = $row[$rowName] ?? "";
// [SEC-3] пароль (хеш) в ответ не попадает - вместо него пустая строка
if ($col->type == "encrypted") { $value = ""; }
array_push($data[$i], $value);
```

**Оригинал (вход):**
```php
$query = "SELECT * FROM NL_USER au WHERE ((au.NL_USER_LOGIN = ?) AND au.NL_USER_PASSWORD = aes_encrypt(?, ?))";
$res = db_prepared($query, array($login, $pass, AESKEY)) or die(db_error($query));
```
**Исправлено:**
```php
$query = "SELECT * FROM NL_USER au WHERE (au.NL_USER_LOGIN = ?)";
$res = db_prepared($query, array($login)) or die(db_error($query));
$row = (db_num_rows($res) > 0) ? db_fetch_assoc($res) : null;
$ok = false;
if ($row !== null) {
    $hash = (string)$row["NL_USER_PASSWORD"];
    $ok = password_verify($pass, $hash);
    if ($ok && password_needs_rehash($hash, PASSWORD_DEFAULT)) { /* UPDATE с новым хешем */ }
} else {
    password_hash($pass, PASSWORD_DEFAULT); // выравниваем время ответа, чтобы не выдавать "логина нет"
}
```

**Что решает.** В базе нет обратимых паролей, клиент не получает ни пароля, ни хеша. Утечка дампа БД не раскрывает пароли пользователей.

---

[🔝 Наверх](#оглавление)
<a id="4-sekrety-v-kode"></a>
### 4. Секреты в коде

**Причина.** Пароль БД в `config.php` попадает в репозиторий и в любые копии кода.

**Исправлено (`php/config.php`, новый):**
```php
define("HOST", $_ENV["HOST"]);
define("USERNAME", $_ENV["USERNAME"]);
define("PASSWORD", $_ENV["PASSWORD"]);
define("DBNAME", $_ENV["DBNAME"]);
```
Дополнительно `display_errors=0`, `log_errors=1`, чтобы пути и тексты запросов не утекали в ответ.

**Что решает.** В репозитории нет секретов.

---

[🔝 Наверх](#оглавление)
<a id="5-csrf-vyhod-sessii-cookie-perebor-parolya"></a>
### 5. CSRF, выход, сессии, cookie, перебор пароля

**CSRF.** Токен хранится в сессии и сравнивается через `hash_equals`. Для JS он лежит в `<meta name="csrf-token">`, а `js.combined.js` добавляет `X-CSRF-Token` ко всем не-GET AJAX-запросам этого сайта. Загрузка файлов идёт собственным XHR библиотеки FileAPI, поэтому там токен передаётся полем `csrf_token`.
```php
function csrf_token_valid() {
    $given = $_SERVER["HTTP_X_CSRF_TOKEN"] ?? ($_POST["csrf_token"] ?? "");
    return is_string($given) && ($given !== "") && hash_equals(csrf_token(), $given);
}
function csrf_check() { /* только POST, иначе 405; неверный токен - 403 */ }
```
```js
// js.combined.js
var csrfToken = $('meta[name="csrf-token"]').attr("content") || "";
$.ajaxPrefilter(function (options, originalOptions, jqXHR) {
    if (!options.crossDomain && !/^(GET|HEAD|OPTIONS)$/i.test(options.type || "GET")) {
        jqXHR.setRequestHeader("X-CSRF-Token", csrfToken);
    }
});
```
Форма входа получила скрытое поле `csrf_token`; `index.php` проверяет его через `csrf_token_valid()`. После успешного входа токен пересоздаётся.

**Выход.** Оригинал `logout.php` выходил по любому запросу (GET). Теперь `csrf_check()` (только POST), а JS вызывает `$.ajax({ url: "/admin/php/logout.php", method: "POST", ... })`.

**`user_logout()` не уничтожал сессию.** Было:
```php
function user_logout() {
    unset($_SESSION["ID_NL_USER"]);
    unset($_SESSION["NL_USER_LOGIN"]);
    ...
}
```
Стало: очистка `$_SESSION`, удаление cookie сессии и `session_destroy()`:
```php
$_SESSION = array();
if (ini_get("session.use_cookies")) { /* setcookie(session_name(), "", [expires в прошлом, те же параметры]) */ }
if (session_status() === PHP_SESSION_ACTIVE) { session_destroy(); }
```

**Cookie сессии.** Было просто `session_start();`. Стало:
```php
ini_set("session.use_strict_mode", "1");
ini_set("session.use_only_cookies", "1");
session_set_cookie_params(array("lifetime" => 0, "path" => "/", "secure" => $nlIsHttps,
                                "httponly" => true, "samesite" => "Strict"));
session_start();
```
`Secure` выставляется при HTTPS (в том числе за прокси по `X-Forwarded-Proto`; подделка заголовка не вредит, меняется только флаг собственной cookie клиента). Cookie с настройками грида (`resizeData2`, `myRowData`) получили `path` и `secure`, а их разбор защищён `try/catch`.

**Перебор пароля.** Таблица `NL_LOGIN_ATTEMPT` и три функции: `login_is_locked`, `login_register_fail`, `login_reset`. Порог: 5 неудач на логин и 30 на IP за 15 минут. Учитывается только `REMOTE_ADDR`: заголовки `X-Forwarded-For` подделываются. Если таблицы нет (миграция не применена), вход не блокируется, ошибка пишется в лог; поэтому миграция из раздела 1 обязательна. Блокировка по логину позволяет «заглушить» чужой аккаунт на 15 минут; это обычный компромисс, а IP-лимит от него не страдает.

**Дополнительно.** `send_security_headers()` отправляет `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'` и HSTS при HTTPS. Полноценный CSP со `script-src` не включён: в проекте много inline-скриптов, нужен рефакторинг, а он запрещён условием.

**Что решает.** Нельзя провести CSRF (включая принудительный logout и login CSRF), нельзя подобрать пароль перебором, сессия не «живёт» после выхода, cookie недоступна JS и не уходит с чужих сайтов.

---

[🔝 Наверх](#оглавление)
<a id="6-stored-xss-i-dom-xss"></a>
### 6. Stored XSS и DOM XSS

**6.1. Содержимое ячеек грида.** jqGrid вставляет значения XML-ответа в ячейки как HTML. Исправлено штатной опцией jqGrid (она сама декодирует значения при заполнении формы редактирования).

```js
// admin/partial/jqgrid.html
datatype : "xml",
// [SEC-6] jqGrid кодирует значения ячеек как HTML-текст
autoencode : true,
```
Для колонок с собственным `formatter` jqGrid ничего не кодирует, поэтому там экранирование ручное (6.2).

**6.2. `photosFormatter` (js.combined.js).**
```js
// было
newValue = '<span class="g-hidden">' + cellvalue + '</span>';
// стало
newValue = '<span class="g-hidden">' + escapeHtml(cellvalue) + '</span>';
```

**6.3. DOM XSS `$.parseHTML($(el).val())` в `dataInit` для фото.**
```js
// было (в PHP-строке dataInit)
var elVal = $.parseHTML($(el).val());
if (elVal) { $(el).val(elVal[1].innerText); }
// стало
$(el).val(extractPhotosValue($(el).val()));
```
```js
function extractPhotosValue(raw) {
    raw = (raw === undefined || raw === null) ? "" : String(raw);
    if (raw.indexOf("<") === -1) { return raw; }
    var doc = new DOMParser().parseFromString(raw, "text/html"); // "мёртвый" документ: скрипты и onerror не выполняются
    var span = doc.querySelector("span.g-hidden");
    return span ? span.textContent : "";
}
```
Старый код ещё и падал, если значение не содержало HTML (`elVal[1]` равно `undefined`).

**6.4. Quill и `JSON.parse(decodeURIComponent(...))`.**
```js
// было: значение ячейки вставляется в атрибут склейкой; символ ' выходит из атрибута
var $div = $("<div id='" + options.id + "' class='g-quill' data-value='" + value + "'>");
...
quill.setContents(JSON.parse(decodeURIComponent($quill_elem.data("value")))); // исключение на мусоре
// стало
var $div = $("<div></div>").attr("id", options.id).addClass("g-quill").attr("data-value", safeValue);
...
function quillParseValue(encoded) {
    try {
        var delta = JSON.parse(decodeURIComponent(encoded));
        if (delta && typeof delta === "object" && $.isArray(delta.ops)) { return delta; }
    } catch (e) {}
    return {ops: []};
}
```
В PHP-части (`afterShowForm`) вызов заменён на `quillParseValue($quill_elem.attr("data-value"))`. На сервере значение «описания» проверяется (формат `{"ops": [...]}`, см. пункт 10). Ссылки и картинки внутри Delta дополнительно фильтрует сам Quill (разрешённые протоколы).

**6.5. Подписи справочников в `<select>` (PHP → строка `value`).** Подпись попадала в HTML `<option>` без экранирования, а символы `;` и `:` ломали формат `"id:текст;id:текст"`. Подпись NL_*_SHORT допускает 25 символов, как раз хватает на `<img src onerror=...>`.
```php
// было
$selectOptions .= ";" . $row[...dbName] . ":" . $row[$selectTableName . "_SHORT"];
// стало
$selectOptions .= ";" . (int)$row[...dbName] . ":" . trim(preg_replace('/[<>&"\';:\s]+/u', " ", (string)$row[$selectTableName . "_SHORT"]));
```
Символы `< > & " ' ; :` заменяются пробелом: так в форме нельзя получить ни HTML, ни разрыв списка. Для этого поля ожидаются обычные подписи справочника.

**6.6. `addFileImg` (js.combined.js)**
```js
// было: имя файла и значение вставлялись как HTML, а значение - ещё и в селектор
img = $("<div>" + name + "</div>")...
wrap.append('<div><input class="full" type="text" value="' + name_val + '" /></div>...');
container.find("img[src='" + src + "']")
// стало
img = $("<div></div>").text(name).data("src", src)...
var fullInput = $('<input class="full" type="text" />').val(name_val);
container.find("img").filter(function () { return $(this).attr("src") === src; })
```
Добавлена проверка `isSafeUploadUrl(src)` (`/^\/img\/[A-Za-z0-9_\-]+\/[A-Za-z0-9_.\-]+$/`): иначе `javascript:`-адрес из БД выполнялся бы при клике через `window.open(src)`. Ответ загрузчика тоже проверяется (мусор вместо URL больше не попадает в список). Также исправлено удаление документа: адрес для них хранится в `data("src")`, а не в атрибуте.

**6.7. `index.php`:** `<?= $page ?>` → `<?= html_esc($page) ?>` (значение и так проходило белый список, но экранируем на выходе).

**Нужен ли `js.combined.js`.** Да: он внесён в архив целиком (`admin/js/js.combined.js`), все правки выше уже в нём.

**Что решает.** Данные из БД выводятся как текст во всех местах: в ячейках, формах, выпадающих списках и списке файлов. Мусор в Delta, URL и cookie не ломает страницу.

---

[🔝 Наверх](#оглавление)
<a id="7-zagruzka-fajlov-i-katalog-img"></a>
### 7. Загрузка файлов и каталог `/img`

**7.1. Исполнение PHP в `/img`.** Добавлен `img/.htaccess`: `php_flag engine off`, запрет `.php/.phtml/.phar/.pht`, `Options -ExecCGI -Indexes`, `nosniff`. Надёжнее задать то же в vhost (`php_admin_flag engine off` или `location ^~ /img/ { location ~ \.php$ { return 403; } }` в nginx): `.htaccess` работает только в Apache при `AllowOverride`.

**7.2. Лимит размера (на сервере).**
```php
$maxBytes = ($colObj->type === "file") ? (20 * 1024 * 1024) : (10 * 1024 * 1024);
$fileSize = @filesize($baseTmpName);
if (($fileSize === false) || ($fileSize <= 0) || ($fileSize > $maxBytes)) { upload_fail("File is too large or empty."); }
```
Клиентские `maxSize` (было 70 и 35 МБ) уменьшены до 20 и 10 МБ, чтобы подсказка не противоречила серверу. Для фото ещё ограничены размеры в пикселях (≤ 10000×10000, как на клиенте).

**7.3. Предсказуемые имена.**
```php
// было
$filename = "/img/" . $dir . "/" . $col . "_" . $id . "_" . $date . "." . $ext;
// стало
$filename = $dirUrl . $col . "_" . bin2hex(random_bytes(16)) . "." . $ext;
```
`id` в имя больше не входит. Значит, при добавлении записи реальный id СУБД и id в форме могут различаться без последствий.

**7.4. Каталоги загрузки и очистки не совпадали.** Загрузка писала в `/img/<table>/`, а очистка искала `/img/objects/<TABLE>/*.jpg`, то есть мусор не удалялся никогда (в данных используется `/img/prop_resale/...`). Теперь каталог один: `ObjectTable::getUploadDirUrl()`, его используют `file.upload.php` и `saveData()`.
```php
// было (saveData): glob по маске id в каталоге, куда ничего не пишется
$imgsPath = $_SERVER["DOCUMENT_ROOT"] . "/img/objects/" . str_replace("NL_", "", $this->dbName) . "/";
$found = glob($imgsPath . ... . "_" . $trueId . "*.jpg");
// стало: удаляются файлы, которые были в записи и пропали из неё; удаление - ПОСЛЕ успешной записи в БД
$oldList = ... decodeUrlList($row_cur[$col->dbName] ?? "");
$newList = ($oper == "del") ? array() : $this->decodeUrlList($post[$col->dbName] ?? "");
foreach ($oldList as $oldUrl) { /* urlToPath() проверяет строгий шаблон имени; is_file(); */ $filesToDelete[] = $oldPath; }
...
foreach ($filesToDelete as $delPath) { @unlink($delPath); }
```
Раньше файлы удалялись до записи, и при ошибке UPDATE данные пропадали.

**7.5. Тип содержимого.** Для фото: `getimagesize()` + тип должен соответствовать расширению (`IMAGETYPE_JPEG` ↔ `jpg/jpeg` и т. д.). Для документов — `finfo` (MIME по содержимому). Файлу выставляется `chmod 0644`, ответ — `application/json` с `nosniff`.

**7.6. URL в поле фото.** Значение поля «Фотографии» раньше записывалось как есть: можно было подставить `javascript:`-адрес и чужой файл. `validateValue()` теперь требует: JSON-список до 50 элементов; каждый элемент соответствует шаблону `/img/<таблица>/<имя>.<расширение>`; файл либо уже был в этой записи, либо загружен этим пользователем в текущей сессии (`$_SESSION["uploaded_files"]`, ограничено 200 записями). Поэтому нельзя «прикрепить» чужой файл, а потом удалить его при правке.

**Что решает.** Нельзя загрузить исполняемый файл и запустить его, угадать URL чужой загрузки, забить диск, подделать тип, а мусорные файлы реально удаляются.

---

[🔝 Наверх](#оглавление)
<a id="8-utechka-kolonki-kontakt-sobstvennika"></a>
### 8. Утечка колонки «Контакт собственника»

**Причина.** `render = false` в `ObjectParam` лишь добавляет `hidden: true` в `colModel`, то есть колонка скрыта в таблице, но значения для неё всё равно приходят в XML. Форма скрывала поле JS-условием.

**Оригинал (`getData`):**
```php
array_push($data[$i], $row[$rowName]);
```
**Исправлено:**
```php
// [SEC-8] "Контакт собственника" отдаётся только владельцу записи и администратору
if ($this->isOwnerContactCol($col) && !$this->canSeeOwnerContact($row)) {
    $value = "";
}
```
```php
public function canSeeOwnerContact($row) {
    return ((int)($_SESSION["ID_NL_USER_PERMISSION"] ?? 0) === 2)
        || ((int)($row["ID_NL_USER"] ?? 0) === (int)($_SESSION["ID_NL_USER"] ?? -1));
}
```
**Побочные каналы.** По этой колонке нельзя было бы искать (`?NL_PROP_RESALE_PHONE_OWNER=+7928` через `LIKE`) и сортировать, подбирая значения. Для не-администраторов колонка исключена из `buildSearchWhere()` и `getSafeOrderBy()` (`isRestrictedCol()`). Клиентская логика формы (скрывать поле у чужих записей) оставлена как удобство.

**Что решает.** Контакт собственника получают только владелец записи и администратор, по XML он не утекает, подобрать его запросами нельзя.

---

[🔝 Наверх](#оглавление)
<a id="9-set-id-php-i-auto-increment"></a>
### 9. `set_id.php` и `AUTO_INCREMENT`

**Причина.** При каждом открытии формы выполнялся `ALTER TABLE ... AUTO_INCREMENT = id + 1`. Каждое открытие или отмена формы «сжигало» номер (DoS нумерации, особенно при анонимном доступе), а два параллельных запроса получали одно значение (гонка). `ALTER` — DDL, он ещё и неявно фиксирует транзакцию.

**Оригинал:**
```php
$query = "ALTER TABLE " . db_ident($tbl) . " AUTO_INCREMENT = " . ($id + 1);
db_query($query);
echo $id;
```
**Исправлено:** `ALTER` удалён, скрипт только читает ориентировочное значение. Остальное — защита (`require_auth()`, `csrf_check()`, право записи в таблицу). Реальный id назначает СУБД: `saveData()` не пишет PK при `add` (колонка id пропускается в `INSERT`), а файлы больше не зависят от id (имена случайные, пункт 7).
```php
// [SEC-9] УДАЛЕНО: ALTER TABLE ... AUTO_INCREMENT = id + 1 при каждом открытии формы.
echo $id;
```
В информационной схеме MySQL 8 значение может быть слегка устаревшим (кеш статистики): число в форме только подсказка, на запись оно не влияет.

**Что решает.** Нет «выжигания» id, гонок и анонимного изменения схемы; параллельные добавления не конфликтуют.

---

[🔝 Наверх](#оглавление)
<a id="10-servernaya-validaciya"></a>
### 10. Серверная валидация

**Причина.** `required`, `maxLength`, тип и допустимые значения проверялись только jqGrid в браузере; прямой POST их не затрагивал (БД лишь обрезала или падала).

**Исправлено.** В `saveData()` каждое поле проходит `validateValue($col, $raw, $oper, $row_cur)` до записи в лог и в БД:

| Правило | Реализация |
|---|---|
| `required` | пустое значение → ошибка (для пароля: только при `add`) |
| `maxLength` | `mb_strlen($raw, "UTF-8") > $col->maxLength` |
| `integer` | целое, не более 10 цифр, \|n\| ≤ 2147483647 |
| `float` | число 0 … 9999.99 (колонки `decimal(6,2)`) |
| `select` | число, значение существует в справочнике: `SELECT 1 FROM <справочник> WHERE ID = ?` |
| `checkbox` | только `Да` / `Нет` |
| `photo/photos/file` | см. пункт 7.6 |
| `rich` | `rawurldecode` → JSON с массивом `ops` |
| пароль | 8–72 байта |

```php
$err = $this->validateValue($col, $raw, $oper, $row_cur);
if ($err !== null) {
    http_response_code(400);
    die("Некорректное значение поля «" . $col->rusName . "»: " . $err);
}
```
Для `ID_NL_USER_PERMISSION` выставлено `required = true` (колонка `NOT NULL`). Проверка существования значения в справочнике закрывает и колонку `ID_NL_USER` в `NL_PROP_RESALE`, у которой в схеме нет внешнего ключа.

**Что решает.** Нельзя записать пустые обязательные поля, слишком длинные значения, мусор в числовые и справочные поля и несуществующие ссылки; данные в БД согласованы с формой.

---

[🔝 Наверх](#оглавление)
<a id="11-korotkie-tegi"></a>
### 11. Короткие теги `<?`

Заменены на `<?php` в `index.php`, `parts/main.php`, `jqgrid.table.php`, `functions.admin.php`, `functions.php`. Конструкции `<?= ... ?>` оставлены (они работают при любом `short_open_tag`). Строка `"<?xml version='1.0' ..."` внутри `showData()` — данные, а не тег, её менять не нужно.

```php
// было
<?
    session_start();
// стало
<?php
    // [SEC-5] Cookie сессии: HttpOnly, Secure, SameSite=Strict ...
```

**Что решает.** Код не ломается и не отдаёт исходники при `short_open_tag=Off`.

---

[🔝 Наверх](#оглавление)
<a id="svodnaya-tablica-vseh-najdennyh-problem"></a>
## Сводная таблица всех найденных проблем

Severity: **Critical** (удалённая компрометация или массовая утечка), **High**, **Medium**, **Low**. Полные фрагменты кода «было/стало» даны в разделах 3–5. В таблице указаны ключевые строки.

| # | Файл | Sev. | Проблема | Оригинал (суть) | Исправление (суть) | Что решает |
|---|---|---|---|---|---|---|
| 1 | `jqgrid.show.php` | Critical | Чтение всех данных анонимом | нет проверки входа | `require_auth();` + право чтения таблицы в конструкторе `ObjectTable` | Аноним и «чужие» роли не получают данные |
| 2 | `jqgrid.edit.php` | Critical | Запись/удаление анонимом | нет проверки входа | `require_auth(); csrf_check();` + права в `saveData()` | Изменять данные могут только вошедшие и только легитимным запросом |
| 3 | `jqgrid.table.php` | High | Разметка и настройки грида анониму | нет проверки входа | `require_auth();` | Структура таблиц и значения справочников не уходят анониму |
| 4 | `set_id.php` | High | Аноним + `ALTER TABLE` | `ALTER TABLE … AUTO_INCREMENT = id+1` | `require_auth(); csrf_check();` + право записи; `ALTER` удалён | Закрыт доступ и убрано «выжигание» id (пункт 9) |
| 5 | `select.get.php` | Medium | Справочники анониму | нет проверки входа | `require_auth();` | Закрыт доступ |
| 6 | `file.upload.php` | Critical | Загрузка файлов анонимом | нет проверки входа | `require_auth(); csrf_check();` + право записи в таблицу | Анонимная загрузка невозможна |
| 7 | `onlymy.php` | Medium | Анонимная запись в сессию, нет CSRF | нет проверки | `require_auth(); csrf_check();` | Закрыт доступ и CSRF |
| 8 | `parts/*.php` | Medium | Прямой доступ анонима, `$_SESSION` без `session_start` | файлы без bootstrap | guard-блок + `require_auth()` (`dicts.php` — только admin) | Части админки не доступны минуя index.php |
| 9 | `saveData()` | Critical | Нет проверки прав на таблицу: пользователь `1` пишет в `NL_USER` и ставит `ID_NL_USER_PERMISSION=2` | проверка владельца сравнивала запись саму с собой | матрица прав `READ/WRITE_PERMISSIONS`, `canAccess()`, проверка владельца по колонке-владельцу, запрет правки админ-строк | Эскалация привилегий невозможна |
| 10 | `saveData()` | High | Mass assignment `ID_NL_USER` | значение брали из формы | для не-админа владелец назначается сервером | Нельзя переназначить запись другому пользователю |
| 11 | `saveData()` | Medium | PK писался из формы | `ID_NL_*` входил в INSERT/UPDATE | PK исключён из INSERT/UPDATE | Нет подмены id и коллизий |
| 12 | `prepareValue()` | Critical | Пароль через обратимый AES (ECB, ключ в коде) | `AES_ENCRYPT(?, ?)` | `password_hash($raw, PASSWORD_DEFAULT)` | Необратимое хранение |
| 13 | `getData()` | Critical | Пароли в открытом виде уходят в грид | `AES_DECRYPT(...)` | выборка удалена, значение `""` | Пароли клиенту не отдаются |
| 14 | `user_auth()` | High | Сравнение пароля в SQL через AES | `... = aes_encrypt(?, ?)` | `password_verify()`, ребэш, выравнивание времени | Безопасная проверка пароля |
| 15 | `php/config.php` | High | Пароль БД и `AESKEY` в исходниках | константы в коде | окружение / ini вне webroot, `display_errors=0` | Нет секретов в репозитории |
| 16 | все POST | High | Нет CSRF | токенов нет | токен в сессии + `meta` + `X-CSRF-Token` + `csrf_check()` | Нельзя совершить действие от имени жертвы |
| 17 | `logout.php` | Medium | Выход по GET | GET | только POST + CSRF | Нет принудительного выхода |
| 18 | `user_logout()` | Medium | Сессия не уничтожалась | `unset` ключей | очистка, удаление cookie, `session_destroy()` | Сессию нельзя «оживить» |
| 19 | `functions.admin.php` | Medium | Cookie без HttpOnly/Secure/SameSite | `session_start()` | `session_set_cookie_params(...)`, strict mode | Кража/подмена cookie осложнена |
| 20 | `user_auth()` | High | Нет защиты от перебора | — | `NL_LOGIN_ATTEMPT`: 5 попыток на логин и 30 на IP за 15 мин | Перебор невозможен |
| 21 | `is_logged_in()` | Medium | Права и существование пользователя проверялись только при входе | данные только из сессии | сверка с БД на каждом запросе + таймаут простоя 2 ч | Удалённый или разжалованный пользователь теряет доступ сразу |
| 22 | заголовки | Low | Нет защиты от clickjacking/MIME-sniffing | — | `X-Frame-Options`, `nosniff`, `Referrer-Policy`, CSP `frame-ancestors`, HSTS | Закрыты базовые векторы |
| 23 | `user_auth()` | Low | Тайминг/перечисление логинов | — | единое сообщение + фиктивное хеширование | Нельзя перечислять логины |
| 24 | `jqgrid.html` | High | Stored XSS: ячейки вставлялись как HTML | нет `autoencode` | `autoencode : true` | Данные из БД выводятся как текст |
| 25 | `js.combined.js` `photosFormatter` | High | Stored XSS через formatter | `cellvalue` без экранирования | `escapeHtml(cellvalue)` | Нет выполнения скриптов из ячейки |
| 26 | `functions.admin.php` (dataInit фото) | High | DOM XSS | `$.parseHTML($(el).val())` | `extractPhotosValue()` через `DOMParser` | Скрипты и `onerror` не выполняются |
| 27 | `js.combined.js` Quill | High | Атрибутная инъекция | `"data-value='" + value + "'"`, `JSON.parse` без защиты | DOM API `.attr()`, `quillParseValue()` | Нет XSS и падения формы |
| 28 | `functions.admin.php` (select) | Medium | XSS через подписи справочника | подпись в строку `value` | чистка символов `< > & " ' ; :`, `(int)` id | Нет XSS и поломки формата списка |
| 29 | `js.combined.js` `addFileImg` | High | XSS через имя файла, инъекция в селектор, `javascript:` в `window.open` | HTML-конкатенация | `.text()`, `.val()`, `filter`, `isSafeUploadUrl()` | Нет выполнения кода из имён и URL |
| 30 | `index.php` | Low | `$page` в HTML без экранирования | `<?= $page ?>` | `html_esc($page)` | Defense in depth |
| 31 | `js.combined.js` cookie | Low | `JSON.parse` куки без защиты | `JSON.parse($.cookie(..))` | `parseCookieJson()` + `secure`, `path` | Подменённая кука не ломает страницу |
| 32 | `/img` | Critical | PHP исполняется в каталоге загрузок | нет ограничений | `img/.htaccess` + рекомендация для vhost/nginx | RCE через загруженный файл невозможен |
| 33 | `file.upload.php` | Medium | Нет лимита размера на сервере | только клиентский `maxSize` | лимит 10 МБ / 20 МБ, размеры ≤ 10000 px | Защита от переполнения диска |
| 34 | `file.upload.php` | Medium | Предсказуемые имена `col_id_дата` | `$col_$id_$date` | `col_<32 hex random_bytes>` | URL файла не угадать |
| 35 | `file.upload.php` / `saveData()` | Medium | Каталоги загрузки и очистки не совпадали | `/img/<table>/` и `/img/objects/<TABLE>/` | единый `getUploadDirUrl()` | Файлы реально удаляются |
| 36 | `file.upload.php` | Medium | Тип файла по расширению | только расширение | тип по содержимому: `getimagesize` + сверка с расширением, `finfo` | Нельзя подменить тип |
| 37 | `saveData()` (фото) | Medium | В поле фото можно записать любой URL/путь; можно удалить чужой файл | значение не валидировалось | шаблон URL + файл из своей сессии или уже в записи; удаление после успешной записи | Нет `javascript:`/чужих файлов |
| 38 | `getData()` | High | «Контакт собственника» уходил всем в XML | `render=false` только прячет колонку | фильтрация на сервере | Утечка закрыта |
| 39 | `buildSearchWhere/getSafeOrderBy` | Medium | Подбор скрытого контакта через поиск/сортировку | колонка участвовала в поиске | колонка исключена для не-владельцев | Нет побочного канала |
| 40 | `set_id.php` | Medium | Гонка и «выжигание» AUTO_INCREMENT | `ALTER TABLE` на каждом открытии формы | чтение без изменения; id назначает СУБД | Нет DoS нумерации и коллизий |
| 41 | `saveData()` | Medium | Нет серверной валидации | проверял только JS | `validateValue()` | Прямой POST не обходит правила |
| 42 | `index.php`, `main.php`, `jqgrid.table.php`, `functions.admin.php`, `functions.php` | Low | Короткие теги `<?` | `<?` | `<?php` | Работает при `short_open_tag=Off` |
| 43 | `index.php` | Low | Закомментирован `user_auth('admin','')` | комментарий-ловушка | удалён | Нет риска случайного включения |
| 44 | `admin/partial/` | Low | Шаблон доступен по HTTP | — | `.htaccess` | Шаблон не публикуется |
| 45 | `random-пароль` (JS) | Medium | `Math.random()` для паролей, 8 символов | `Math.random().toString(36)` | `crypto.getRandomValues`, 12 символов | Стойкий пароль |
| 46 | `index.php` | Low | Протокол-относительный `//api-maps…` | `//api-maps…` | `https://` | Нет загрузки по http |
| 47 | `showOnlyMy` | Low (не правил) | Владелец определяется по неуникальному `NL_USER_SHORT` | сравнение с именем | не менялось: это только UI-подсказка, права проверяет сервер | см. раздел 6 |

---
