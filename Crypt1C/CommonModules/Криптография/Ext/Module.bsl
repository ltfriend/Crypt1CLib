﻿///////////////////////////////////////////////////////////////////////////////////////////////////////
// (с) Tolkachev Pavel, 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
///////////////////////////////////////////////////////////////////////////////////////////////////////

#Область ПрограммныйИнтерфейс

// Вычисляет HMAC с использованием SHA-256.
//
// Параметры:
//   Ключ - Строка, ДвоичныеДанные - секретный ключ.
//   Данные - Строка, ДвоичныеДанные - данные, для которых необходимо вычислить HMAC-SHA256.
//
// Возвращаемое значение:
//   ДвоичныеДанные - вычисленное значение HMAC-SHA256.
//
Функция HMACSHA256(Знач Ключ, Данные) Экспорт
	Если ТипЗнч(Ключ) = Тип("Строка") Тогда
		Ключ = ПолучитьДвоичныеДанныеИзСтроки(Ключ);
	КонецЕсли;
	ДвоичныеДанные = ?(ТипЗнч(Данные) = Тип("Строка"), ПолучитьДвоичныеДанныеИзСтроки(Данные), Данные);
	ВнешняяКомпонента = КриптографияСерверПовтИсп.ПодключитьКомпонентуКриптографии();
	Возврат ВнешняяКомпонента.HMACSHA256(Ключ, ДвоичныеДанные);
КонецФункции

// Вычисляет PBKDF2 с использованием SHA-512.
//
// Параметры:
//  Пароль - Строка - пароль (входной ключ).
//  Соль - Строка, ДвоичныеДанные - соль.
//  ДлинаКлюча - Строка - длина ключа.
//  КоличествоИтераций - Число - количество итераций (рекомендуемое значение от 600000 до 1000000).
// 
// Возвращаемое значение:
//  ДвоичныеДанные
//
Функция PBKDF2SHA512(Знач Пароль, Знач Соль, Знач ДлинаКлюча, Знач КоличествоИтераций = 600000) Экспорт
	ДвоичныеДанныеПароля = ПолучитьДвоичныеДанныеИзСтроки(Пароль);
	ДвоичныеДанныеСоли = ?(ТипЗнч(Соль) = Тип("Строка"), ПолучитьДвоичныеДанныеИзСтроки(Соль), Соль);
	ВнешняяКомпонента = КриптографияСерверПовтИсп.ПодключитьКомпонентуКриптографии();
	Возврат ВнешняяКомпонента.PBKDF2SHA512(ДвоичныеДанныеПароля, ДвоичныеДанныеСоли, ДлинаКлюча, КоличествоИтераций);
КонецФункции

// Выполняет шифрование данных по алгоритму AES-256-CBC.
//
// Параметры:
//  Данные - ДвоичныеДанные - данные для шифрования.
//  Ключ - ДвоичныеДанные - ключ шифрования.
//  ВекторИнициализации - ДвоичныеДанные - вектор инициализации (IV).
// 
// Возвращаемое значение:
//  ДвоичныеДанные - зашифрованные данные.
//
Функция ЗашифроватьAES(Данные, Знач Ключ, Знач ВекторИнициализации) Экспорт
	ВнешняяКомпонента = КриптографияСерверПовтИсп.ПодключитьКомпонентуКриптографии();
	Возврат ВнешняяКомпонента.EncryptAES(Данные, Ключ, ВекторИнициализации);
КонецФункции

// Выполняет шифрование данных по алгоритму AES-256-CBC по указанному паролю и соли.
//
// Параметры:
//  Данные - ДвоичныеДанные - данные для шифрования.
//  Пароль - Строка - пароль для шифрования данных.
//  Соль - Строка, ДвоичныеДанные, Неопределено - соль, если не указана, то будет сгенерирована длиной в 8 байт. В этом
//                                                случае на выходе будет содержать сгенерированное значение соли.
//  КоличествоИтераций - Число - количество итераций для вычисления ключа (рекомендуемое значение от 600000 до 1000000).
// 
// Возвращаемое значение:
//  ДвоичныеДанные - зашифрованные данные.
//
Функция ЗашифроватьAESПоПаролю(Данные, Знач Пароль, Соль = Неопределено, Знач КоличествоИтераций = 600000) Экспорт
	Если Соль = Неопределено Тогда
		Соль = СлучайныеДвоичныеДанные(8);
	КонецЕсли;
	ДвоичныеДанныеСоли = ?(ТипЗнч(Соль) = Тип("Строка"), ПолучитьДвоичныеДанныеИзСтроки(Соль), Соль);
	КлючИВектор = КлючИВекторИнициализацииПоПаролю(Пароль, ДвоичныеДанныеСоли, КоличествоИтераций);
	Возврат ЗашифроватьAES(Данные, КлючИВектор.Ключ, КлючИВектор.Вектор);
КонецФункции

// Генерирует новый вектор инициализации для алгоритма шифрования AES.
// 
// Возвращаемое значение:
//  ДвоичныеДанные - вектор инициализации алгоритма шифрования AES.
//
Функция НовыйВекторИнициализацииAES() Экспорт
	Возврат СлучайныеДвоичныеДанные(16);
КонецФункции

// Генерирует новый ключ для алгоритма шифрования AES.
// 
// Возвращаемое значение:
//  ДвоичныеДанные - ключ для алгоритма шифрования AES.
//
Функция НовыйКлючAES() Экспорт
	Возврат СлучайныеДвоичныеДанные(32);
КонецФункции

// Выполняет расшифровку данных, зашифрованных по алгоритму AES-256-CBC.
//
// Параметры:
//  ЗашифрованныеДанные - ДвоичныеДанные - зашифрованные данные.
//  Ключ - ДвоичныеДанные - ключ шифрования.
//  ВекторИнициализации - ДвоичныеДанные - вектор инициализации (IV).
// 
// Возвращаемое значение:
//  ДвоичныеДанные
//
Функция РасшифроватьAES(ЗашифрованныеДанные, Знач Ключ, Знач ВекторИнициализации) Экспорт
	ВнешняяКомпонента = КриптографияСерверПовтИсп.ПодключитьКомпонентуКриптографии();
	Возврат ВнешняяКомпонента.DecryptAES(ЗашифрованныеДанные, Ключ, ВекторИнициализации);
КонецФункции

// Выполняет расшифровку данных, зашифрованных по алгоритму AES-256-CBC по указанному при шифровании паролю и соли.
//
// Параметры:
//  ЗашифрованныеДанные - ДвоичныеДанные - зашифрованные данные.
//  Пароль - Строка - пароль, использованный при шифровании.
//  Соль - Строка, ДвоичныеДанные - соль, использованная при шифровании.
//  КоличествоИтераций - Число - количество итераций для вычисления ключа, использованное при шифровании.
// 
// Возвращаемое значение:
//  ДвоичныеДанные
//
Функция РасшифроватьAESПоПаролю(ЗашифрованныеДанные, Знач Пароль, Знач Соль, Знач КоличествоИтераций = 600000) Экспорт
	ДвоичныеДанныеСоли = ?(ТипЗнч(Соль) = Тип("Строка"), ПолучитьДвоичныеДанныеИзСтроки(Соль), Соль);
	КлючИВектор = КлючИВекторИнициализацииПоПаролю(Пароль, ДвоичныеДанныеСоли, КоличествоИтераций);
	Возврат РасшифроватьAES(ЗашифрованныеДанные, КлючИВектор.Ключ, КлючИВектор.Вектор);
КонецФункции

// Генерирует случайные данные с помощью криптографически безопасного псевдослучайного генератора (CSPRNG).
//
// Параметры:
//  Размер - Число - размер данных (количество байт).
// 
// Возвращаемое значение:
//  ДвоичныеДанные
//
Функция СлучайныеДвоичныеДанные(Знач Размер) Экспорт
	ВнешняяКомпонента = КриптографияСерверПовтИсп.ПодключитьКомпонентуКриптографии();
	Возврат ВнешняяКомпонента.RANDbytes(Размер);
КонецФункции

#КонецОбласти

#Область СлужебныйПрограммныйИнтерфейс

Функция ПодключитьКомпонентуКриптографии() Экспорт
	Если Не ПодключитьВнешнююКомпоненту(
				"ОбщийМакет.КомпонентаКриптографии",
				"com_ptolkachev_Crypt1CLibExtension",
				ТипВнешнейКомпоненты.Native)
	Тогда
		ВызватьИсключение НСтр("ru='Не удалось подключить внешнюю компоненту криптографии'");
	КонецЕсли;
	
	ВнешняяКомпонента = Новый("AddIn.com_ptolkachev_Crypt1CLibExtension.com_ptolkachev_Crypt1CLibExtension");
	Возврат ВнешняяКомпонента;
КонецФункции

#КонецОбласти

#Область СлужебныеПроцедурыИФункции

Функция КлючИВекторИнициализацииПоПаролю(Пароль, Соль, КоличествоИтераций) Экспорт
	ДлинаКлюча = 32;   // 256 бит
	ДлинаВектора = 16; // 128 бит
	
	Хеш = PBKDF2SHA512(Пароль, Соль, ДлинаКлюча + ДлинаВектора, КоличествоИтераций);
	
	ЧтениеДанных = Новый ЧтениеДанных(Хеш);
	
	Результат = ЧтениеДанных.Прочитать(ДлинаКлюча);
	Ключ = Результат.ПолучитьДвоичныеДанные();
	
	Результат = ЧтениеДанных.Прочитать(ДлинаВектора);
	Вектор = Результат.ПолучитьДвоичныеДанные();
	
	ЧтениеДанных.Закрыть();
	
	Результат = Новый Структура;
	Результат.Вставить("Ключ", Ключ);
	Результат.Вставить("Вектор", Вектор);
	Возврат Результат;
КонецФункции

#КонецОбласти
