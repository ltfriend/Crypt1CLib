# Библиотека для работы с криптографией на платформе 1С:Предприятие 8

Предоставляет интерфейс для работы с базовыми методами криптографии:
- шифрование и расшифровка данных по алгоритму AES-256;
- генерация случайных данных с помощью криптографически безопасного псевдослучайного генератора (CSPRNG, типичный сценарий использования - генерация ключа и вектора инициализации (IV) для алгоритма шифрования AES-256);
- вычисление HMAC криптографической хеш-функцией SHA-256 (типичный сценарий использования - подписание сообщений);
- формирование ключа на основе пароля PBKDF2 криптографической хеш-функцией SHA-512 (типичный сценарий использования - получение криптографически стойких хешей паролей).

Функции криптографии реализованы в виде внешней Native компоненты с использованием библиотеки OpenSSL версии 3. Компонента работает в операционных системах Windows и Linux. Для Windows версии компоненты библиотека OpenSSL прилинкована статически и не требует установки дополнительного программного обеспечения. В Linux для использования компоненты данная библиотека должна быть установлена в системе (в большинстве современных дистрибутивов Linux данная библиотека уже включена в состав, что так же не требует дополнительных действий).

Для работы с криптографией используется общий серверный модуль **Криптография**.

Так же, в состав библиотеки входит обработка, демонстрирующая различные способы работы с методами криптографии.

### Описание методов общего модуля Криптография

**HMACSHA256**

**Синтаксис:**  
HMACSHA256(Ключ, Данные)

**Параметры:**  
*Ключ (Строка, ДвоичныеДанные)* - секретный ключ.  
*Данные (Строка, ДвоичныеДанные)* - данные, для которых необходимо вычислить HMAC-SHA256.  

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Вычисляет HMAC с использованием SHA-256.

---

**PBKDF2SHA512**

**Синтаксис:**  
PBKDF2SHA512(Пароль, Соль, ДлинаКлюча, КоличествоИтераций)

**Параметры:**  
*Пароль (Строка)* - пароль (входной ключ).  
*Соль (Строка, ДвоичныеДанные)* - соль.  
*ДлинаКлюча (Число)* - длина ключа.  
*КоличествоИтераций (Число), Необязательный* - количество итераций. Рекомендуемое значение от 600000 до 1000000. В целях повышения безопасности не стоит использовать значения меньше 600000. Значение по умолчанию: 600000

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Формирует ключ PBKDF2 с использованием хеш-функции SHA-512.

---

**ЗашифроватьAES**

**Синтаксис:**  
ЗашифроватьAES(Данные, Ключ, ВекторИнициализации)

**Параметры:**  
*Данные (ДвоичныеДанные)* - данные для шифрования.  
*Ключ (ДвоичныеДанные)* - ключ шифрования.  
*ВекторИнициализации (ДвоичныеДанные)* - вектор инициализации (IV).

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Выполняет шифрование данных по алгоритму AES-256-CBC.

---

**ЗашифроватьAESПоПаролю**  

**Синтаксис:**  
ЗашифроватьAESПоПаролю(Данные, Пароль, Соль, КоличествоИтераций)

**Параметры:**  
*Данные (ДвоичныеДанные*) - данные для шифрования.  
*Пароль (Строка)* - пароль для шифрования данных.  
*Соль (Строка, ДвоичныеДанные), Необязательный* - соль. Если параметр не указан, то будет сгенерирована новая соль длиной в 8 байт. В этом случае на выходе будет содержать сгенерированное значение соли. Значение по умолчанию: Неопределено  
*КоличествоИтераций (Число), Необязательный* - количество итераций для вычисления ключа. Рекомендуемое значение от 600000 до 1000000. В целях повышения безопасности не стоит использовать значения меньше 600000. Значение по умолчанию: 600000

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Выполняет шифрование данных по алгоритму AES-256-CBC. Для генерации ключа и вектора инициализации (IV) используется пароль и соль.

---

**РасшифроватьAES**  

**Синтаксис:**  
РасшифроватьAES(ЗашифрованныеДанные, Ключ, ВекторИнициализации)

**Параметры:**  
*ЗашифрованныеДанные (ДвоичныеДанные)* - зашифрованные данные.  
*Ключ (ДвоичныеДанные)* - ключ, использованный при шифровании данных.  
*ВекторИнициализации (ДвоичныеДанные)* - вектор инициализации (IV), использованный при шифровании данных.

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Выполняет расшифровку данных, зашифрованных по алгоритму AES-256-CBC.

---

**РасшифроватьAESПоПаролю**

**Синтаксис:**  
РасшифроватьAESПоПаролю(ЗашифрованныеДанные, Пароль, Соль, КоличествоИтераций)

**Параметры:**  
*ЗашифрованныеДанные (ДвоичныеДанные)* - зашифрованные данные.  
*Пароль (Строка)* - пароль, использованный при шифровании.  
*Соль (Строка, ДвоичныеДанные)* - соль, использованная при шифровании.  
*КоличествоИтераций (Число)* - количество итераций для вычисления ключа, использованное при шифровании.

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Выполняет расшифровку данных, зашифрованных по алгоритму AES-256-CBC по указанному при шифровании паролю и соли функцией **ЗашифроватьAESПоПаролю**.

---

**НовыйКлючAES**

**Синтаксис:**  
НовыйКлючAES()

**Параметры:**  
Нет

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Генерирует новый ключ для алгоритма шифрования AES с помощью криптографически безопасного псевдослучайного генератора (CSPRNG).

---

**НовыйВекторИнициализацииAES**

**Синтаксис:**  
НовыйВекторИнициализацииAES()

**Параметры:**  
Нет

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Генерирует новый вектор инициализации для алгоритма шифрования AES с помощью криптографически безопасного псевдослучайного генератора (CSPRNG).

---

**СлучайныеДвоичныеДанные**

**Синтаксис:**  
СлучайныеДвоичныеДанные(Размер)

**Параметры:**  
*Размер (Число)* - размер данных (количество байт).

**Возвращаемое значение:**  
ДвоичныеДанные

**Описание:**  
Генерирует случайные данные с помощью криптографически безопасного псевдослучайного генератора (CSPRNG).

### Добавление библиотеки в состав основной конфигурации

1. Создайте пустую конфигурацию 1С:Предприятие и загрузите конфигурацию из файлов. Для этого в меню выберите пункт **Конфигурация > Загрузить конфигурацию из файлов**. В окне загрузке установите переключатель **Загрузить из** в значение **XML-файлы** (установлен по умолчанию) и укажите путь на диске к каталогу **Crypt1C**.
2. Сохраните загруженную конфигурацию в .cf-файл. Для этого в меню выберите пункт **Конфигурация > Сохранить конфигурацию в файл** и укажите файл для сохранения.
3. Откройте конфигуратор основной информационной базы 1С:Предприятие.
4. В меню выберите пункт **Конфигурация > Сравнить, объединить с конфигурацией из файла**.
5. Выберите на диске файл, в который была выгружена конфигурации библиотеки криптографии в пункте 2.
6. В окне сравнения, объединения снимите флаги со всех объектов метаданных.
7. В командной панели окна сравнения, объединения в подменю **Действия** выберите пункт **Отметить по подсистемам файла** и установите флаг только на подсистеме **Криптография**.
8. Нажмите кнопку **Выполнить** для объединения библиотеки с основной конфигурацией.
9. Сохраните изменения конфигурации и обновите конфигурацию базы данных (пункт меню **Конфигурация > Обновить конфигурацию базы данных**).

При необходимости, вместо основной конфигурации библиотеку можно включить в состав расширения. Для этого скопируйте в расширение следующие объекты метаданных из конфигурации библиотеки, полученной при выполнении п.1:
- общий модуль **Криптография**;
- общий модуль **КриптографияСерверПовтИсп**;
- общий макет **КомпонентаКриптографии**.

### Сборка внешней компоненты для работы с криптографией

В состав библиотеки уже включена скомпилированная версия внешней компоненты для ОС Windows и Linux. В папке **Crypt1CLib** находятся исходные коды данной компоненты. При необходимости вы можете самостоятельно выполнить компиляцию и сборку. Более подробная информация описана в файле [VNCOMPINSTALL.md](https://github.com/ltfriend/Crypt1CLib/blob/master/VNCOMPINSTALL.md)