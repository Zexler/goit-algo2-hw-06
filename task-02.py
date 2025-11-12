import mmh3            # Високоякісний некриптографічний хеш-алгоритм
import math            # Для математичних функцій (log, power)
import time            # Для вимірювання часу виконання (benchmark)
import json            # Для парсингу JSON-рядків
from tabulate import tabulate # Для форматованого виводу таблиці

# --- Клас HyperLogLog ---
class HyperLogLog:
    """
    Реалізація алгоритму HyperLogLog для оцінки кардинальності
    (кількості унікальних елементів).
    """
    # Конструктор класу
    def __init__(self, p=14): 
        # p: кількість бітів для індексації (визначає кількість регістрів)
        self.p = p
        # m: кількість регістрів, m = 2^p. (1 << p - це швидший спосіб обчислити 2^p)
        self.m = 1 << p
        # Ініціалізація m регістрів нулями. 
        self.registers = [0] * self.m
        # alpha: Константа корекції, залежна від m
        self.alpha = self._get_alpha()
        # Порогове значення для корекції малих діапазонів (Linear Counting)
        self.small_range_correction = 5 * self.m / 2

    # Метод для визначення константи alpha_m
    def _get_alpha(self):
        """ Обчислює константу alpha_m для корекції гармонійного середнього. """
        # Використовуємо більш точні типові константи HLL:
        if self.m == 16: # p=4
            return 0.673
        elif self.m == 32: # p=5
            return 0.697
        elif self.m == 64: # p=6
            return 0.709
        # Для m >= 128 (p >= 7) використовується загальна формула
        else: 
            return 0.7213 / (1 + 1.079 / self.m)

    # Метод додавання нового елемента
    def add(self, item):
        """ Додає елемент для оцінки кардинальності. """
        # Хешуємо елемент у 32-бітове беззнакове ціле число
        x = mmh3.hash(str(item), seed=0xDEADBEEF, signed=False) 
        
        # j: Використовуємо молодші p бітів хешу як індекс регістра
        j = x & (self.m - 1)
        
        # w: Старші (32-p) бітів хешу, використовуємо для обчислення rho
        w = x >> self.p
        
        # Оновлюємо регістр j максимальним значенням rho(w)
        self.registers[j] = max(self.registers[j], self._rho(w))

    # Метод обчислення rho
    def _rho(self, w):
        """ Обчислює позицію першої (найменш значущої) одиниці + 1. """
        # Якщо старші біти (w) нульові
        if w == 0:
            return 32
        
        # Обчислюємо позицію першої 1 (Longest Run of Leading Zeros + 1)
        return 32 - w.bit_length() + 1 

    # Метод оцінки кардинальності
    def count(self):
        """ Оцінює кардинальність. """
        # Z: Обчислення гармонійного середнього
        Z = sum(2.0 ** -r for r in self.registers)
        
        # E: Сира (Raw) оцінка кардинальності: E = alpha * m^2 / Z
        E = self.alpha * self.m * self.m / Z
        
        # Корекція малих значень (Small Range Correction)
        if E <= self.small_range_correction:
            # V: Кількість нульових регістрів
            V = self.registers.count(0) 
            if V > 0:
                # Лінійна оцінка: E = m * ln(m / V)
                return self.m * math.log(self.m / V)
        
        # Повертаємо сиру оцінку (або скориговану, якщо V=0)
        return E

# --- Методи підрахунку та завантаження даних ---

def load_data(filename="lms-stage-access.log"):
    """
    1. Метод завантаження даних обробляє лог-файл (формат JSON Lines), 
    вилучаючи 'remote_addr' та ігноруючи некоректні рядки.
    Код адаптований до великих наборів даних (читання по рядках).
    """
    # print(f"Завантаження та парсинг IP-адрес із файлу: {filename}...")
    ip_addresses = []
    
    try:
        # Відкриття та читання файлу (читання по рядках)
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                # Перевірка, чи рядок не порожній, і початок схожий на JSON
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue # Ігноруємо порожні або некоректні рядки
                
                try:
                    # Парсинг JSON-рядка
                    record = json.loads(line)
                    # Вилучення IP-адреси з ключа "remote_addr"
                    ip = record.get("remote_addr")
                    
                    # Перевірка, чи IP-адреса знайдена і не є порожньою
                    if ip:
                        # Додаємо знайдену IP-адресу до списку
                        ip_addresses.append(ip)
                except json.JSONDecodeError:
                    # Ігноруємо рядки, які не є коректним JSON
                    continue
        
        # Перевірка, чи були знайдені дані
        if not ip_addresses:
            print("Файл знайдено, але не знайдено жодної коректної IP-адреси.")
            raise ValueError("Не знайдено коректних даних для обробки.")
        
        print(f"Успішно завантажено {len(ip_addresses)} записів.")
        return ip_addresses
    
    except FileNotFoundError:
        # Критична помилка, якщо файл не знайдено
        print(f"Критична помилка: Файл '{filename}' не знайдено.")
        print("Будь ласка, створіть або перемістіть 'lms-stage-access.log' для продовження.")
        # Викидаємо виняток, щоб зупинити виконання без даних
        raise
    except ValueError:
        # Викидаємо виняток, якщо дані некоректні
        raise

def count_exact(data):
    """
    2. Функція точного підрахунку повертає правильну кількість унікальних IP-адрес.
    """
    start_time = time.perf_counter()
    # Точний підрахунок за допомогою множини (set)
    unique_count = len(set(data))
    end_time = time.perf_counter()
    return unique_count, end_time - start_time

def count_hll(data, p=14):
    """
    3. Реалізує наближений підрахунок за допомогою HyperLogLog (з прийнятною похибкою).
    """
    start_time = time.perf_counter()
    # Створення екземпляра HLL
    hll = HyperLogLog(p=p)
    # Послідовне додавання всіх елементів
    for item in data:
        hll.add(item)
    # Оцінка кардинальності
    estimated_count = hll.count()
    end_time = time.perf_counter()
    return estimated_count, end_time - start_time

# --- Основна частина скрипту ---
def main():
    try:
        # 1. Завантаження даних з лог-файлу (JSONL формат)
        all_ips = load_data()
    except Exception as e:
        # Зупиняємо виконання, якщо файл не знайдено або дані некоректні
        print(f"Помилка виконання: {e}")
        return
    
    # Загальна кількість записів у лозі
    total_records = len(all_ips)
    # print("-" * 50)
    
    # 2. та 4. Точний підрахунок
    exact_count, exact_time = count_exact(all_ips)
    # print(f"Точний підрахунок завершено.")

    # 3. та 4. Наближений підрахунок HyperLogLog (p=14 дає ~0.8% стандартної похибки)
    hll_count, hll_time = count_hll(all_ips, p=14)
    # print(f"HyperLogLog (p=14) підрахунок завершено.")
    
    # print("-" * 50)
    
    # 4. Представлення результатів у вигляді таблиці
    
    # Розрахунок похибки
    absolute_error = abs(hll_count - exact_count)
    relative_error = (absolute_error / exact_count) * 100 if exact_count > 0 else 0
    
    # Формування даних для таблиці
    table_data = [
        # ["Загальна кількість записів", f"{total_records:.0f}", f"{total_records:.0f}"],
        ["Унікальні елементи", f"{exact_count:.0f}", f"{hll_count:.0f}"],
        ["Час виконання (сек.)", f"{exact_time:.4f}", f"{hll_time:.4f}"],
        ["Абсолютна похибка", "N/A", f"{absolute_error:.2f}"],
        ["Відносна похибка", "N/A", f"{relative_error:.2f} %"],
    ]
    
    # Вивід заголовка
    print("## Результати порівняння:")
    # Вивід таблиці
    print(tabulate(table_data, 
                   headers=["Показник", "Точний підрахунок (Set)", "HyperLogLog (HLL)"], 
                   tablefmt="fancy_grid", 
                   numalign="right"))

    
# Запуск головної функції
if __name__ == "__main__":
    main()







