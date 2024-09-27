cmake_minimum_required(VERSION 3.10)

# Название проекта и язык программирования
project(KuzFileCryptor
    VERSION 1.0
    DESCRIPTION "Утилита для шифрования/расшифрования файлов с использованием алгоритма Кузнечик"
    LANGUAGES C
)

# Установка стандарта C
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_EXTENSIONS OFF)

# Определение исходных файлов
set(SOURCES
    file_encryptor.c
    # Добавьте сюда другие исходные файлы, если они есть
)

# Определение дополнительных путей для поиска библиотек и заголовков
# Пользователь может переопределить эти пути при вызове CMake
set(AKRYPT_BASE_LIBRARY_DIR "" CACHE PATH "Путь к библиотеке libakrypt-base")
set(AKRYPT_LIBRARY_DIR "" CACHE PATH "Путь к библиотеке libakrypt")
set(AKRYPT_INCLUDE_DIR "" CACHE PATH "Путь к заголовочным файлам libakrypt")

# Добавление директорий заголовочных файлов
if(AKRYPT_INCLUDE_DIR)
    include_directories(${AKRYPT_INCLUDE_DIR})
endif()

# Поиск библиотек libakrypt-base и libakrypt
find_library(LIBAKRYPT_BASE
    NAMES akrypt-base libakrypt-base
    PATHS ${AKRYPT_BASE_LIBRARY_DIR} /usr/lib /usr/local/lib
    NO_DEFAULT_PATH
)

find_library(LIBAKRYPT
    NAMES akrypt libakrypt
    PATHS ${AKRYPT_LIBRARY_DIR} /usr/lib /usr/local/lib
    NO_DEFAULT_PATH
)

# Проверка, найдены ли библиотеки
if(NOT LIBAKRYPT_BASE)
    find_library(LIBAKRYPT_BASE_LIB akrypt-base)
    if(NOT LIBAKRYPT_BASE_LIB)
        message(FATAL_ERROR "Библиотека libakrypt-base не найдена. Пожалуйста, установите ее или укажите путь вручную.")
    else()
        set(LIBAKRYPT_BASE ${LIBAKRYPT_BASE_LIB})
    endif()
endif()

if(NOT LIBAKRYPT)
    find_library(LIBAKRYPT_LIB akrypt)
    if(NOT LIBAKRYPT_LIB)
        message(FATAL_ERROR "Библиотека libakrypt не найдена. Пожалуйста, установите ее или укажите путь вручную.")
    else()
        set(LIBAKRYPT ${LIBAKRYPT_LIB})
    endif()
endif()

# Добавление исполняемого файла
add_executable(KuzFileCryptor ${SOURCES})

# Связывание с библиотеками
target_link_libraries(KuzFileCryptor PRIVATE ${LIBAKRYPT_BASE} ${LIBAKRYPT})

# Опционально: установка исполняемого файла
install(TARGETS KuzFileCryptor
    RUNTIME DESTINATION bin
)

# -----------------------------
# Настройка Doxygen
# -----------------------------

# Поиск Doxygen
find_package(Doxygen REQUIRED)

if(DOXYGEN_FOUND)
    # Указать директорию для документации
    set(DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")

    # Указать входной файл для Doxygen
    set(DOXYGEN_IN "${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in")
    set(DOXYGEN_OUT "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")

    # Обработка шаблона Doxyfile.in
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    # Добавление цели для генерации документации
    add_custom_target(doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Генерация документации Doxygen"
        VERBATIM
    )

    # Опционально: установка документации
    install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}/html DESTINATION share/doc/${PROJECT_NAME})
else()
    message(WARNING "Doxygen не найден. Документация не будет сгенерирована.")
endif()
