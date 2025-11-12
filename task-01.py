import mmh3
# Імпорт необхідних типів для анотації, що покращує читабельність та перевірку коду.
from typing import List, Dict, Union

class BloomFilter:
    """
    Реалізація фільтра Блума для швидкої, імовірнісної перевірки наявності елементів.
    Використовується для економії пам'яті, оскільки не зберігає самі елементи.
    """
    def __init__(self, size: int, num_hashes: int):
        """
        Конструктор класу BloomFilter.

        :param size: Розмір бітового масиву (кількість бітів, M). Чим більше, тим менше хибнопозитивних спрацьовувань.
        :param num_hashes: Кількість хеш-функцій (K), які будуть використані для кожного елемента.
        """
        # Перевірка вхідних параметрів: вони мають бути додатними цілими числами.
        if not (isinstance(size, int) and size > 0 and 
                isinstance(num_hashes, int) and num_hashes > 0):
            raise ValueError("Size та num_hashes мають бути додатними цілими числами.")
            
        self.size: int = size
        self.num_hashes: int = num_hashes
        # Ініціалізація бітового масиву нулями. Кожен елемент (біт) позначає, чи було встановлено певний індекс.
        self.bit_array: List[int] = [0] * size

    def add(self, item: str) -> None:
        """
        Додає елемент (пароль) до фільтра Блума, встановлюючи відповідні біти в 1.
        
        :param item: Елемент для додавання (очікується рядок).
        """
        # Технічна умова 3: Обробка порожніх або некоректних значень. Якщо пароль недійсний, ігноруємо його.
        if not item or not isinstance(item, str):
             return
        
        # mmh3 краще працює з байтами. Перетворюємо рядок у послідовність байтів (UTF-8).
        data = item.encode('utf-8')

        # Обчислюємо num_hashes різних хешів
        for i in range(self.num_hashes):
            # Використовуємо лічильник 'i' як 'seed' (початкове значення) для mmh3.
            # Зміна 'seed' забезпечує, що кожен виклик дає інший хеш.
            # signed=False гарантує, що результат хешу буде позитивним.
            hash_value = mmh3.hash(data, i, signed=False)
            
            # Обмежуємо хеш-значення розміром масиву (M) за допомогою операції modulo.
            index = hash_value % self.size
            
            # Встановлюємо біт за обчисленим індексом в 1.
            self.bit_array[index] = 1

    def contains(self, item: str) -> bool:
        """
        Перевіряє наявність елемента у фільтрі.
        
        :param item: Елемент для перевірки (очікується рядок).
        :return: True, якщо елемент ймовірно присутній (можливий хибнопозитивний результат); 
                 False, якщо елемент точно відсутній.
        """
        # Обробка порожніх або некоректних значень: вони не могли бути додані, тому повертаємо False.
        if not item or not isinstance(item, str):
             return False
        
        # Перетворення на байти для коректного хешування.
        data = item.encode('utf-8')

        # Обчислюємо ті ж num_hashes індексів.
        for i in range(self.num_hashes):
            # Обчислення хешу з тим самим 'seed' для отримання того ж індексу.
            hash_value = mmh3.hash(data, i, signed=False)
            index = hash_value % self.size
            
            # Якщо хоча б один з необхідних бітів дорівнює 0, це означає, що елемент ТОЧНО не був доданий.
            if self.bit_array[index] == 0:
                return False
                
        # Якщо всі K бітів встановлені в 1, елемент, ймовірно, присутній.
        return True

# ----------------------------------------------------------------------

def check_password_uniqueness(bloom_filter: BloomFilter, new_passwords: List[Union[str, None]]) -> Dict[str, str]:
    """
    Перевіряє унікальність списку нових паролів, використовуючи наданий фільтр Блума.
    
    :param bloom_filter: Ініціалізований екземпляр BloomFilter з раніше використаними паролями.
    :param new_passwords: Список паролів для перевірки на унікальність.
    :return: Словник {пароль: статус}, де статус — "унікальний" або "вже використаний" тощо.
    """
    results: Dict[str, str] = {}
    
    # Ітерація по кожному паролю в списку
    for password in new_passwords:
        # Технічна умова 3: Обробка порожніх або некоректних значень (None, порожній рядок, інший тип).
        if not password or not isinstance(password, str):
            # Ключ словника має бути рядком, тому приводимо до str.
            key = str(password)
            results[key] = "некоректний або порожній"
            continue 

        # Використовуємо метод contains() фільтра Блума для перевірки.
        if bloom_filter.contains(password):
            # Якщо contains() повертає True, це означає, що пароль, ймовірно, вже був доданий.
            results[password] = "вже використаний"
        else:
            # Якщо contains() повертає False, пароль точно не був доданий (це унікальний пароль).
            results[password] = "унікальний"
            
    return results

# ----------------------------------------------------------------------

if __name__ == "__main__":    
    # print("--- Запуск перевірки унікальності паролів за допомогою фільтра Блума ---")     
    # Ініціалізація фільтра Блума 
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Список паролів, які вважаються вже існуючими (були використані).
    existing_passwords = ["password123", "admin123", "qwerty123"]
    # print(f"\n1. Додавання існуючих паролів до фільтра: {existing_passwords}")
    for password in existing_passwords:
        bloom.add(password)
    
    # Список нових паролів для перевірки. Містить дублікати ("password123", "admin123") та некоректні значення.
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest", "", None]
    # print(f"2. Перевірка списку нових паролів: {new_passwords_to_check}\n")     
    # Виклик основної функції перевірки.
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    print("--- Результати перевірки ---")
    for password, status in results.items():
        # Форматування виводу для коректного відображення порожнього рядка та None.
        display_password = f"'{password}'" if password not in ("None", "") else f"({password})"
        
        # Виведення результату у відповідності до очікуваного формату.
        print(f"Пароль {display_password} — {status}.")
