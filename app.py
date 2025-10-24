from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
import string
import json
import os

app = Flask(__name__)
app.secret_key = 'your_strong_and_unique_secret_key'

# Имя файла для хранения данных пользователей
USER_DATA_FILE = 'users.json'


# --- Функции для работы с файлом данных ---

def load_user_data():
    """Загружает данные пользователей из JSON-файла. Возвращает словарь."""
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as f:
            try:
                # Пытаемся загрузить данные; если файл пуст, возвращаем пустой словарь
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_user_data(data):
    """Сохраняет данные пользователей в JSON-файл."""
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)


# --- Декоратор и Вспомогательные функции (без изменений) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols):
    # ... (Ваша функция генерации пароля без изменений) ...
    characters = ''
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return "Ошибка: вы должны выбрать хотя бы один тип символов."

    length = max(4, min(length, 128))
    password = ''.join(random.choice(characters) for i in range(length))
    return password


# --- Маршруты приложения ---

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    # ... (Логика index без изменений, использует session['username']) ...
    password = None
    username = session.get('username', 'Пользователь')

    length = 12
    use_lowercase = True
    use_uppercase = True
    use_digits = True
    use_symbols = False

    if request.method == 'POST':
        try:
            length = int(request.form.get('length'))
            use_lowercase = 'lowercase' in request.form
            use_uppercase = 'uppercase' in request.form
            use_digits = 'digits' in request.form
            use_symbols = 'symbols' in request.form

            if not (use_lowercase or use_uppercase or use_digits or use_symbols):
                password = "Ошибка: выберите хотя бы один тип символов."
            else:
                password = generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols)

        except (ValueError, TypeError):
            password = "Ошибка: пожалуйста, введите действительную длину."

    messages = session.pop('_flashes', [])

    return render_template(
        'index.html',
        password=password,
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        username=username,
        messages=messages
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Загружаем данные
        user_data = load_user_data()

        if username in user_data:
            error = 'Пользователь с таким именем уже существует.'
        elif not username or not password:
            error = 'Логин и пароль не могут быть пустыми.'
        else:
            # Хешируем пароль
            hashed_password = generate_password_hash(password)

            # Добавляем нового пользователя
            user_data[username] = {'password_hash': hashed_password}

            # Сохраняем данные обратно в файл
            save_user_data(user_data)

            # Автоматический вход
            session['logged_in'] = True
            session['username'] = username
            flash(f'Пользователь "{username}" успешно зарегистрирован и авторизован!', 'success')
            return redirect(url_for('index'))

    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Загружаем данные
        user_data = load_user_data()

        user = user_data.get(username)

        if user and check_password_hash(user['password_hash'], password):
            # Авторизация успешна.
            session['logged_in'] = True
            session['username'] = username
            flash('Вы успешно вошли!', 'success')

            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        else:
            error = 'Неправильный логин или пароль.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # При старте сервера можно проверить, существует ли файл и создать тестового пользователя, если его нет
    data = load_user_data()
    if 'test' not in data:
        data['test'] = {'password_hash': generate_password_hash('test')}
        save_user_data(data)
        print("Тестовый пользователь создан и сохранен в users.json: Логин 'test', Пароль 'test'")

    app.run(debug=True)