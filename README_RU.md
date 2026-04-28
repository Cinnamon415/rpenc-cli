# rpenc-cli
[Русский](README_RU.md) [English](README.md)

Инструмент портативного шифрования на Rust, созданный для защиты данных на переносных (и не только) накопителях.

Запустите *generator.sh* или *generator.bat* для создания папок и файлов rpenc в директории запуска.
Запустите *rpenc.sh* или *rpenc.bat* из командной строки для запуска rpenc.
- [Использование](#Использование)
- [Установка](#Установка)
- [Именование файлов](#Именование-файлов)
- [Прогресс](#Прогресс)

## Установка
Unix:
```bash
curl -o "generator.sh" "https://raw.githubusercontent.com/Cinnamon415/rpenc-cli/refs/heads/main/generator.sh"
chmod +x ./generator.sh
./generator.sh
```
Windows:
```batch
curl -o "generator.bat" "https://raw.githubusercontent.com/Cinnamon415/rpenc-cli/refs/heads/main/generator.bat"
./generator.bat
```


## Использование
```
Usage: rpenc <COMMAND>

Commands:
  encrypt
  decrypt
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
```
Usage: rpenc encrypt [OPTIONS]

Options:
  -i, --input <INPUT>
  -o, --output <OUTPUT>
  -d, --delete-origins
  -n, --file-name <FILE_NAME>
  -f, --full
  -h, --help                   Print help
```
```
Usage: rpenc decrypt [OPTIONS]

Options:
  -i, --input <INPUT>
  -o, --output <OUTPUT>
  -d, --delete-origin
  -h, --help             Print help
```
Без аргументов --input или --output команда `rpenc encrypt` шифрует файлы в родительской директории папки rpenc. Зашифрованные файлы по умолчанию сохраняются в `rpenc/encrypted/`.
**Аргументы input и output должны быть директориями**
Используйте `--delete-origins` или `-d` при `encrypt`, если хотите удалить файлы и папки, которые будут зашифрованы.

## Именование файлов
|Имя                                              |Режим
|-------------------------------------------------|----------------------------------------|
|`encrypted-data-1766044242.087331609s-3294.enc`  |По умолчанию                            |
|`[NAME]-1766044242.087331609s-3294.enc`          |`--file-name [NAME]` или `-n`           |
|`[NAME].enc`                                     |`--file-name [NAME] --full` или `-fn`   |

## Прогресс
- [x] Архивация
- [x] Шифрование/Дешифрование
- [x] Аргументы
- [ ] Конфигурация
- [ ] GUI
- [ ] Режим AES и аппаратное ускорение

## Нужна помощь в тестировании

Если вы хотите помочь протестировать **rpenc-cli** на различных платформах:
1. Создайте новый issue с меткой **`Testing`**
2. Укажите в отчете:
   - Скриншоты или короткое видео, демонстрирующее проблему
   - Полный вывод программы
   - Название и версию вашей операционной системы (например, Windows 11 22H2, macOS Sonoma 14.5, Ubuntu 24.04)
   - Четкие шаги для воспроизведения проблемы

> 🏆 **Охотники за багами**: Пользователи, сообщившие о подтвержденных проблемах, будут отмечены в разделе **Особая благодарность** в примечаниях к следующему релизу!

Ваша обратная связь очень ценна и помогает сделать rpenc-cli надежнее для всех.

---

### Важное примечание
Поскольку у меня нет доступа к нескольким операционным системам для всестороннего тестирования, я не могу обеспечить бесперебойную работу ***RPENC*** на всех устройствах. **Ваш вклад** в виде тестирования на вашем устройстве был бы неоценим для обеспечения кроссплатформенной совместимости.
