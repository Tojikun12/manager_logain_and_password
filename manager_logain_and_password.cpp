#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <cctype>
#include <limits>
#include <windows.h>
#include <algorithm>
#include <climits>
#include <cstdio>

#ifdef max
#undef max
#endif

using namespace std;

struct Record { int id; string service, login, password; };

vector<Record> records;
string masterPassword, DATA_FILE;
int currentCipherMethod = 1;

// Прототипы
string cipherCaesar(const string&, int);
string decipherCaesar(const string&, int);
string cipherXOR(const string&, const string&);
string decipherXOR(const string&, const string&);
int selectCipherMethod();
string getDataFileName(int);
Record encryptRecord(const Record&, const string&, int);
Record decryptRecord(const Record&, const string&, int);
void loadData(), saveData();
bool isStrongPassword(const string&);
string generatePassword(int, bool, bool, bool, bool);
bool loginExists(const string&, const string&);
void addRecord(), showAll(), showOne(), editRecord(), deleteRecord(), exportToTXT(), importFromTXT();

int inputInt(const string& prompt, int minVal = 0, int maxVal = INT_MAX) {
    int val;
    while (true) {
        cout << prompt;
        cin >> val;
        if (cin.fail() || val < minVal || val > maxVal) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Ошибка ввода. Повторите.\n";
        }
        else {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return val;
        }
    }
}

string cipherCaesar(const string& text, int shift) {
    int shiftAlpha = (shift % 26 + 26) % 26;
    int shiftDigit = (shift % 10 + 10) % 10;
    string result = text;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = static_cast<char>((c - base + shiftAlpha) % 26 + base);
        }
        else if (isdigit(c)) {
            c = static_cast<char>((c - '0' + shiftDigit) % 10 + '0');
        }
    }
    return result;
}

string decipherCaesar(const string& text, int shift) { return cipherCaesar(text, -shift); }

string cipherXOR(const string& text, const string& key) {
    string result = text;
    for (size_t i = 0; i < result.size(); ++i)
        result[i] ^= key[i % key.size()];
    return result;
}

string decipherXOR(const string& text, const string& key) { return cipherXOR(text, key); }

int selectCipherMethod() {
    cout << "\nВыберите метод шифрования:\n1. Шифр Цезаря\n2. XOR\nВыберите (1-2): ";
    return inputInt("", 1, 2);
}

string getDataFileName(int method) { return method == 1 ? "passwords_caesar.dat" : "passwords_xor.dat"; }

Record encryptRecord(const Record& rec, const string& masterPass, int method) {
    Record encrypted = rec;
    int shift = 0;
    for (char c : masterPass) shift += c;
    shift = shift % 26 + 3;
    if (method == 1) {
        encrypted.service = cipherCaesar(rec.service, shift);
        encrypted.login = cipherCaesar(rec.login, shift);
        encrypted.password = cipherCaesar(rec.password, shift);
    }
    else {
        encrypted.service = cipherXOR(rec.service, masterPass);
        encrypted.login = cipherXOR(rec.login, masterPass);
        encrypted.password = cipherXOR(rec.password, masterPass);
    }
    return encrypted;
}

Record decryptRecord(const Record& rec, const string& masterPass, int method) {
    Record decrypted = rec;
    int shift = 0;
    for (char c : masterPass) shift += c;
    shift = shift % 26 + 3;
    if (method == 1) {
        decrypted.service = decipherCaesar(rec.service, shift);
        decrypted.login = decipherCaesar(rec.login, shift);
        decrypted.password = decipherCaesar(rec.password, shift);
    }
    else {
        decrypted.service = decipherXOR(rec.service, masterPass);
        decrypted.login = decipherXOR(rec.login, masterPass);
        decrypted.password = decipherXOR(rec.password, masterPass);
    }
    return decrypted;
}

void saveData() {
    ofstream file(DATA_FILE, ios::binary | ios::trunc);
    if (!file.is_open()) { cout << "Ошибка сохранения!\n"; return; }
    char methodChar = static_cast<char>(currentCipherMethod);
    file.write(&methodChar, sizeof(methodChar));
    size_t count = records.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& rec : records) {
        file.write(reinterpret_cast<const char*>(&rec.id), sizeof(rec.id));
        auto writeStr = [&](const string& s) {
            size_t len = s.size();
            file.write(reinterpret_cast<const char*>(&len), sizeof(len));
            file.write(s.c_str(), len);
        };
        writeStr(rec.service);
        writeStr(rec.login);
        writeStr(rec.password);
    }
    file.close();
}

void loadData() {
    ifstream file(DATA_FILE, ios::binary);
    if (!file.is_open()) return;
    char methodChar;
    file.read(&methodChar, sizeof(methodChar));
    if (file.fail()) { file.close(); remove(DATA_FILE.c_str()); return; }
    currentCipherMethod = (methodChar == 1 || methodChar == 2) ? methodChar : 1;
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (file.fail()) { file.close(); remove(DATA_FILE.c_str()); return; }
    records.clear();
    for (size_t i = 0; i < count; ++i) {
        Record rec;
        file.read(reinterpret_cast<char*>(&rec.id), sizeof(rec.id));
        if (file.fail()) break;
        auto readStr = [&](string& s) {
            size_t len;
            file.read(reinterpret_cast<char*>(&len), sizeof(len));
            if (file.fail()) return;
            s.resize(len);
            file.read(&s[0], len);
        };
        readStr(rec.service);
        readStr(rec.login);
        readStr(rec.password);
        records.push_back(rec);
    }
    file.close();
}

bool isStrongPassword(const string& password) {
    if (password.length() < 8) return false;
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    for (char c : password) {
        if (islower(c)) hasLower = true;
        else if (isupper(c)) hasUpper = true;
        else if (isdigit(c)) hasDigit = true;
        else if (specialChars.find(c) != string::npos) hasSpecial = true;
    }
    return hasLower && hasUpper && hasDigit && hasSpecial;
}

string generatePassword(int length, bool upper, bool lower, bool digits, bool special) {
    string chars;
    if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (digits) chars += "0123456789";
    if (special) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    if (chars.empty()) chars = "abcdefghijklmnopqrstuvwxyz";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, chars.size() - 1);
    string password;
    for (int i = 0; i < length; ++i) password += chars[dis(gen)];
    return password;
}

bool loginExists(const string& service, const string& login) {
    for (const auto& rec : records) {
        Record dec = decryptRecord(rec, masterPassword, currentCipherMethod);
        if (dec.service == service && dec.login == login) return true;
    }
    return false;
}

void addRecord() {
    Record newRecord;
    newRecord.id = records.empty() ? 1 : records.back().id + 1;
    cout << "\n=== ДОБАВЛЕНИЕ ЗАПИСИ ===\n";
    cout << "Сервис: "; getline(cin, newRecord.service);

    bool cancelled = false;
    bool updated = false;

    while (true) {
        cout << "Логин: "; getline(cin, newRecord.login);
        if (newRecord.login.empty()) {
            cout << "Логин не может быть пустым.\n";
            continue;
        }

        auto it = find_if(records.begin(), records.end(),
            [&](const Record& rec) {
                Record dec = decryptRecord(rec, masterPassword, currentCipherMethod);
                return dec.service == newRecord.service && dec.login == newRecord.login;
            });

        if (it != records.end()) {
            cout << "Запись с сервисом \"" << newRecord.service
                << "\" и логином \"" << newRecord.login << "\" уже существует.\n";
            cout << "1. Обновить пароль\n2. Ввести другой логин\n3. Отменить добавление\n";
            int choice = inputInt("Выберите (1-3): ", 1, 3);

            if (choice == 1) {
                Record decrypted = decryptRecord(*it, masterPassword, currentCipherMethod);
                cout << "Текущий пароль: " << decrypted.password << "\n";

                cout << "Способ ввода пароля:\n1. Вручную\n2. Сгенерировать\nВыберите: ";
                int passChoice = inputInt("", 1, 2);
                string newPassword;
                if (passChoice == 1) {
                    do {
                        cout << "Новый пароль (мин. 8 символов): ";
                        getline(cin, newPassword);
                        if (!isStrongPassword(newPassword))
                            cout << "Ненадёжный пароль. Попробуйте снова.\n";
                    } while (!isStrongPassword(newPassword));
                }
                else {
                    int length = inputInt("Длина пароля (8-25): ", 8, 25);
                    newPassword = generatePassword(length, true, true, true, true);
                    cout << "Сгенерированный пароль: " << newPassword << "\n";
                }
                decrypted.password = newPassword;
                *it = encryptRecord(decrypted, masterPassword, currentCipherMethod);
                saveData();
                cout << "Пароль обновлён.\n";
                updated = true;
                break;
            }
            else if (choice == 2) {
                continue;
            }
            else {
                cout << "Добавление отменено.\n";
                cancelled = true;
                break;
            }
        }
        else {
            break;
        }
    }

    if (!cancelled && !updated) {
        cout << "Способ ввода пароля:\n1. Вручную\n2. Сгенерировать\nВыберите: ";
        int passChoice = inputInt("", 1, 2);
        if (passChoice == 1) {
            do {
                cout << "Пароль (мин. 8 символов): ";
                getline(cin, newRecord.password);
                if (!isStrongPassword(newRecord.password))
                    cout << "Ненадёжный пароль. Попробуйте снова.\n";
            } while (!isStrongPassword(newRecord.password));
        }
        else {
            int length = inputInt("Длина пароля (8-25): ", 8, 25);
            newRecord.password = generatePassword(length, true, true, true, true);
            cout << "Сгенерированный пароль: " << newRecord.password << "\n";
        }
        records.push_back(encryptRecord(newRecord, masterPassword, currentCipherMethod));
        saveData();
        cout << "Запись добавлена.\n";
    }
}

void showAll() {
    if (records.empty()) { cout << "Нет записей.\n"; return; }
    cout << "\n=== ВСЕ ЗАПИСИ ===\n";
    for (const auto& rec : records) {
        Record dec = decryptRecord(rec, masterPassword, currentCipherMethod);
        cout << "ID: " << rec.id << " | Сервис: " << dec.service << " | Логин: " << dec.login << "\n";
    }
}

void showOne() {
    if (records.empty()) { cout << "Нет записей.\n"; return; }
    int id = inputInt("Введите ID записи: ", 1);
    for (const auto& rec : records) {
        if (rec.id == id) {
            Record decrypted = decryptRecord(rec, masterPassword, currentCipherMethod);
            cout << "\n=== ЗАПИСЬ ID " << id << " ===\n";
            cout << "Сервис: " << decrypted.service << "\n";
            cout << "Логин: " << decrypted.login << "\n";
            cout << "Пароль: " << decrypted.password << "\n";
            return;
        }
    }
    cout << "Запись с ID " << id << " не найдена.\n";
}

void editRecord() {
    if (records.empty()) { cout << "Нет записей.\n"; return; }
    int id = inputInt("Введите ID записи для редактирования: ", 1);
    for (auto& rec : records) {
        if (rec.id == id) {
            Record decrypted = decryptRecord(rec, masterPassword, currentCipherMethod);
            cout << "\nРедактирование ID " << id << "\n";
            cout << "Текущий сервис: " << decrypted.service << "\nНовый (Enter – оставить): ";
            string tmp; getline(cin, tmp); if (!tmp.empty()) decrypted.service = tmp;
            cout << "Текущий логин: " << decrypted.login << "\nНовый (Enter – оставить): ";
            getline(cin, tmp); if (!tmp.empty()) decrypted.login = tmp;
            cout << "Текущий пароль: " << decrypted.password << "\nНовый (Enter – оставить): ";
            getline(cin, tmp);
            if (!tmp.empty()) {
                if (isStrongPassword(tmp)) decrypted.password = tmp;
                else cout << "Пароль ненадёжный, оставлен старый.\n";
            }
            rec = encryptRecord(decrypted, masterPassword, currentCipherMethod);
            saveData();
            cout << "Запись обновлена.\n";
            return;
        }
    }
    cout << "Запись не найдена.\n";
}

void deleteRecord() {
    if (records.empty()) { cout << "Нет записей.\n"; return; }
    int id = inputInt("Введите ID записи для удаления: ", 1);
    for (auto it = records.begin(); it != records.end(); ++it) {
        if (it->id == id) {
            records.erase(it);
            saveData();
            cout << "Запись удалена.\n";
            return;
        }
    }
    cout << "Запись не найдена.\n";
}

void exportToTXT() {
    if (records.empty()) { cout << "Нет записей для экспорта.\n"; return; }
    string filename;
    cout << "Имя файла (например, backup.txt): ";
    getline(cin, filename);
    if (filename.empty()) filename = "passwords_export.txt";
    ofstream file(filename);
    if (!file.is_open()) { cout << "Ошибка создания файла.\n"; return; }
    file << "ID\tСервис\tЛогин\tПароль\n";
    for (const auto& rec : records) {
        Record decrypted = decryptRecord(rec, masterPassword, currentCipherMethod);
        string srv = decrypted.service, log = decrypted.login, pwd = decrypted.password;
        replace(srv.begin(), srv.end(), '\t', ' ');
        replace(log.begin(), log.end(), '\t', ' ');
        replace(pwd.begin(), pwd.end(), '\t', ' ');
        file << decrypted.id << "\t" << srv << "\t" << log << "\t" << pwd << "\n";
    }
    file.close();
    cout << "Экспорт выполнен в " << filename << "\n";
}

void importFromTXT() {
    string filename;
    cout << "Имя файла для импорта: ";
    getline(cin, filename);
    if (filename.empty()) { cout << "Имя не указано.\n"; return; }
    ifstream file(filename);
    if (!file.is_open()) { cout << "Не удалось открыть файл.\n"; return; }
    string line;
    getline(file, line);
    int imported = 0, skipped = 0;
    while (getline(file, line)) {
        if (line.empty()) continue;
        size_t p1 = line.find('\t'), p2 = line.find('\t', p1 + 1), p3 = line.find('\t', p2 + 1);
        if (p1 == string::npos || p2 == string::npos || p3 == string::npos) { skipped++; continue; }
        string service = line.substr(p1 + 1, p2 - p1 - 1);
        string login = line.substr(p2 + 1, p3 - p2 - 1);
        string password = line.substr(p3 + 1);
        if (loginExists(service, login)) {
            cout << "Пропущен дубликат: " << service << " / " << login << "\n";
            skipped++;
            continue;
        }
        Record newRecord;
        newRecord.id = records.empty() ? 1 : records.back().id + 1;
        newRecord.service = service;
        newRecord.login = login;
        newRecord.password = password;
        records.push_back(encryptRecord(newRecord, masterPassword, currentCipherMethod));
        imported++;
    }
    file.close();
    if (imported > 0) { saveData(); cout << "Импортировано: " << imported << "\n"; }
    else cout << "Не импортировано ни одной записи.\n";
    if (skipped > 0) cout << "Пропущено: " << skipped << "\n";
}

int main() {
    setlocale(LC_ALL, "rus");
    cout << "==========================================\n";
    cout << "   ОРГАНАЙЗЕР ЛОГИНОВ И ПАРОЛЕЙ v1.4\n";
    cout << "==========================================\n";

    string entered;
    cout << "\nВведите мастер-пароль для доступа: ";
    getline(cin, entered);
    if (entered != "jjiolk") {
        cout << "Неверный пароль. Доступ запрещён.\n";
        return 1;
    }
    masterPassword = "jjiolk";
    cout << "Пароль принят. Добро пожаловать!\n";

    int chosenMethod = selectCipherMethod();
    DATA_FILE = getDataFileName(chosenMethod);

    ifstream test(DATA_FILE, ios::binary);
    bool fileExists = test.is_open();
    test.close();

    if (!fileExists) {
        currentCipherMethod = chosenMethod;
        cout << "Создан новый файл: " << DATA_FILE << "\n";
        saveData();
    }
    else {
        loadData();
        cout << "Загружен файл: " << DATA_FILE << "\n";
        cout << "Метод шифрования: " << (currentCipherMethod == 1 ? "Цезаря" : "XOR") << "\n";
        if (chosenMethod != currentCipherMethod)
            cout << "ВНИМАНИЕ: вы выбрали метод " << (chosenMethod == 1 ? "Цезаря" : "XOR")
            << ", но файл содержит " << (currentCipherMethod == 1 ? "Цезаря" : "XOR")
            << ". Будет использован метод из файла.\n";
        cout << "Загружено записей: " << records.size() << "\n";
    }

    int choice;
    do {
        cout << "\n==========================================\n";
        cout << "ГЛАВНОЕ МЕНЮ\n";
        cout << "1. Добавить запись\n2. Показать все\n3. Показать по ID\n";
        cout << "4. Редактировать\n5. Удалить\n6. Экспорт в TXT\n7. Импорт из TXT\n8. Выйти\n";
        choice = inputInt("Выберите (1-8): ", 1, 8);
        switch (choice) {
        case 1: addRecord(); break;
        case 2: showAll(); break;
        case 3: showOne(); break;
        case 4: editRecord(); break;
        case 5: deleteRecord(); break;
        case 6: exportToTXT(); break;
        case 7: importFromTXT(); break;
        case 8: cout << "До свидания!\n"; break;
        }
    } while (choice != 8);

    return 0;
}