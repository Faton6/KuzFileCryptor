/*!
 * \file
 * \brief Файл с кодом программы для шифрования/расшифрования симметричным алгоритмом Кузнечик
 * \author Антон Фахретдинов
 * \version 1.0
 * \date Сентябрь 2024 года
 * \warning Данная программа не является надежным средством шифрования данных.
 * \warning Также данная программа написана с использованием небезопасных функций библиотеки stdio.h
 *
 * Данная утилита предназначена для шифрования произвольных файлов с ключом, вырабатываемым из пароля, введенным пользователем в консольный интерфейс.
 * Консольный интерфейс реализован с применением функций getopt (файл <getopt.h>).
 *
 * Библиотека, используемая для шифрования - libakrypt (https://git.miem.hse.ru/axelkenzo/libakrypt-0.x)
 *
 * В библиотеке libakrypt принято соглашение, по которому каждый ключ предназначается для одного или небольшого класса однотипных криптографических преобразований, т.е. ключ шифрования данных нельзя использовать для их имитовставки или выработки электронной подписи.
 */

#include <stdio.h>        //!< Стандартная библиотека для работы с I/O интерфейсами.
#include <stdlib.h>       //!< Стандартная библиотека для работы с операционной системой.
#include <libakrypt.h>    //!< Не стандартная библиотека для работы с криптографическими алгоритмами.
#include <getopt.h>       //!< Стандартная библиотека для работы с консольным управлением.

#define BUFFER_SIZE 48    //!< Размер буфера для потоковой обработки - основан на длине блочного шифра.

/*!
 * \brief Функция для вывода справки
 *
 * Данная функция выводит справку по флагам программы. Справка выводится в случае,
 * если программа была запущена без флагов, либо с неправильными флагами.
 *
 * \param prog_name Имя программы, используемое в сообщениях справки.
 */
void print_usage(const char *prog_name) {
    fprintf(stderr, "Использование: %s [-e | -d] -i <файл> -p <пароль>\n", prog_name);
    fprintf(stderr, "    -e            Режим шифрования\n");
    fprintf(stderr, "    -d            Режим расшифровки\n");
    fprintf(stderr, "    -i <файл>     Входной файл\n");
    fprintf(stderr, "    -p <пароль>   Пароль\n");
}

/*!
 * \brief Функция для шифрования/расшифрования файла.
 *
 * Данная функция принимает указатели на файл, требующий шифрования/расшифровки, и пароль, введенный пользователем.
 * В функции применяется симметричное шифрование - алгоритм Кузнечик. В связи с этим она в равной степени выполняет
 * функции шифрования и расшифрования.
 *
 * \details
 * **Локальные переменные:**
 * - `error` — код ошибки, возвращаемый функциями библиотеки.
 * - `ctx` — контекст секретного ключа.
 * - `iv` — значение синхропосылки.
 * - `in_buffer` — буфер для чтения.
 * - `out_buffer` — буфер для записи.
 * - `bytes_read` — количество прочитанных байт.
 *
 * \param[in] fin Указатель на исходный файл.
 * \param[out] fout Указатель на результирующий файл.
 * \param[in] password Пароль для операции шифрования/расшифрования.
 * \return Статус выполненной работы. Возвращает `EXIT_SUCCESS` при ошибке, `EXIT_FAILURE` при успешном выполнении.
 */
int file_modify(FILE* fin, FILE* fout, char password[]) {
    int error = ak_error_ok;

    struct bckey ctx; 

    ak_uint8 iv[8] = { 0x03, 0x07, 0xae, 0xf1, 0x00, 0x00, 0x00, 0x00 };

    if (ak_libakrypt_create(NULL) != ak_true) {
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    ak_uint8 *in_buffer = malloc(BUFFER_SIZE); 
    ak_uint8 *out_buffer = malloc(BUFFER_SIZE); 
    if (in_buffer == NULL || out_buffer == NULL) {
        fprintf(stderr, "Ошибка: невозможно выделить память для буферов\n");
        free(in_buffer);
        free(out_buffer);
        return EXIT_FAILURE;
    }

    size_t bytes_read;

    ak_bckey_create_oid(&ctx, ak_oid_find_by_name("kuznechik"));
    ak_bckey_set_key_from_password(&ctx, password, strlen(password), "rand", 4);

    bytes_read = fread(in_buffer, 1, BUFFER_SIZE, fin);
    if ((error = ak_bckey_ctr(&ctx, in_buffer, out_buffer, 48, iv, 8)) != ak_error_ok) goto ex_error;
    fwrite(out_buffer, 1, bytes_read, fout);

    while ((bytes_read = fread(in_buffer, 1, BUFFER_SIZE, fin)) == BUFFER_SIZE) {
        if ((error = ak_bckey_ctr(&ctx, in_buffer, out_buffer, 48, NULL, 0)) != ak_error_ok) goto ex_error;

        fwrite(out_buffer, 1, bytes_read, fout);
    }
    if ((error = ak_bckey_ctr(&ctx, in_buffer, out_buffer, bytes_read, NULL, 0)) != ak_error_ok) goto ex_error;
    fwrite(out_buffer, 1, bytes_read, fout);

ex_error:
    ak_bckey_destroy(&ctx);
    ak_libakrypt_destroy();

    free(in_buffer);
    free(out_buffer);

    if (error != ak_error_ok) return EXIT_SUCCESS;
    else return EXIT_FAILURE;
}

/*!
 * \brief Главная функция программы.
 *
 * Программа принимает на вход аргументы в виде флагов для шифрования или расшифровки,
 * входного файла и пароля. В зависимости от флагов выполняет соответствующую операцию.
 *
 * \details
 * **Локальные переменные:**
 * - `exitstatus` — Статус выполнения программы.
 * - `opt` — контекст секретного ключа.
 * - `input_filename` — Имя входного файла.
 * - `password` — Пароль для шифрования/расшифрования.
 * - `encrypt_flag` — Флаг режима шифрования.
 * - `out_filename_len` — Длина имени создаваемого файла.
 * - `output_filename` — Имя создаваемого файла.
 * - `len_input_filename` — Длина имени принимаемого файла.
 * - `enc_suffix` — Суффикс обозначающий, что файл зашифрован.
 * - `fin` — Указатель на принимаемый файл.
 * - `fout` — Указатель на создаваемый файл.
 * \param[in] argc Количество аргументов командной строки.
 * \param[in] argv Массив строк аргументов командной строки.
 * \return Статус завершения работы программы. `EXIT_SUCCESS` при успешном выполнении, `EXIT_FAILURE` при ошибке.
 */
int main(int argc, char *argv[]) {

    int exitstatus = EXIT_FAILURE;

    int opt;
    char *input_filename = NULL;
    char *password = NULL;
    int encrypt_flag = 2;
	size_t out_filename_len;
	char *output_filename;
	size_t len_input_filename;
	const char *enc_suffix = ".enc";
	FILE *fin;
	FILE *fout;
	
    while ((opt = getopt(argc, argv, "edi:p:")) != -1) {
        switch (opt) {
            case 'e':
                encrypt_flag = 1;
                break;
            case 'd':
                encrypt_flag = 0;
                break;
            case 'i':
                input_filename = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (encrypt_flag == 2) {
        fprintf(stderr, "Ошибка: необходимо выбрать либо -e (шифрование), либо -d (расшифровка)\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (input_filename == NULL) {
        fprintf(stderr, "Ошибка: необходимо указать входной файл с помощью -i\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (password == NULL) {
        fprintf(stderr, "Ошибка: необходимо указать пароль с помощью -p\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strlen(input_filename) > 249) {
        fprintf(stderr, "Ошибка: Имя файла слишком длинное!\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    fin = fopen(input_filename, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Ошибка: Невозможно открыть файл '%s'\n", input_filename);
        return EXIT_FAILURE;
    }

    out_filename_len = strlen(input_filename) + 5; 
    output_filename = malloc(out_filename_len);
    if (output_filename == NULL) {
        fprintf(stderr, "Ошибка: невозможно выделить память\n");
        fclose(fin);
        return EXIT_FAILURE;
    }

    if (encrypt_flag) {
        snprintf(output_filename, out_filename_len, "%s.enc", input_filename);
    } else {
        
        len_input_filename = strlen(input_filename);
        if (len_input_filename > strlen(enc_suffix) && strcmp(input_filename + len_input_filename - strlen(enc_suffix), enc_suffix) == 0) {
            snprintf(output_filename, out_filename_len, "%.*s.dec", (int)len_input_filename - strlen(enc_suffix), input_filename);
        } else {
            snprintf(output_filename, out_filename_len, "%s.dec", input_filename);
        }
    }

    fout = fopen(output_filename, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Ошибка при открытии выходного файла '%s'\n", output_filename);
        fclose(fin);
        free(output_filename);
        return EXIT_FAILURE;
    }

    exitstatus = file_modify(fin, fout, password);

    fclose(fin);
    fclose(fout);
    free(output_filename);

    return exitstatus;
}

