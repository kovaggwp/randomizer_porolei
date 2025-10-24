import os
import random
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g
# Используем werkzeug.security для безопасного хранения хешей паролей
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# ВАЖНО: замените 'your_strong_and_unique_secret_key' на сложный, уникальный ключ
app.secret_key = 'your_strong_and_unique_secret_key'

# Конфигурация базы данных
DATABASE = 'my_database.db'


# --- 1. Функции для работы с базой данных ---

def get_db():
    """Открывает новое соединение с базой данных, если оно еще не открыто."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # Позволяет получать строки как объекты с доступом по имени колонки (например, row['username'])
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Закрывает соединение с базой данных в конце запроса."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Инициализирует таблицы Users и Passwords."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 1. Таблица Users (для регистрации/логина)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        # 2. Таблица Passwords (для хранения учетных записей)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site TEXT,
                login_site TEXT,
                password_site TEXT NOT NULL,
                time TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES Users(id)
            )
        """)
        db.commit()


# --- 2. Вспомогательные функции и декораторы ---

def get_user_id(username):
    """Получает ID пользователя по его имени."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM Users WHERE username = ?", (username,))
    row = cursor.fetchone()
    return row['id'] if row else None


def login_required(f):
    """Декоратор, требующий авторизации."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Для доступа к этой странице необходимо войти.', 'info')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# --- 3. Роуты аутентификации ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = (request.form.get('username') or '').strip()
        p = request.form.get('password') or ''

        if not u or not p:
            flash('Заполните все поля.', 'error')
            return render_template('register.html')

        db = get_db()
        cursor = db.cursor()

        # Хешируем пароль перед сохранением
        password_hash = generate_password_hash(p)

        try:
            cursor.execute("INSERT INTO Users (username, password_hash) VALUES (?, ?)", (u, password_hash))
            db.commit()

            session['username'] = u
            session['role'] = 'user'
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Пользователь с таким именем уже существует.', 'error')
            return render_template('register.html')
        except Exception as e:
            flash(f'Ошибка регистрации: {e}', 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = (request.form.get('username') or '').strip()
        p = request.form.get('password') or ''

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, password_hash FROM Users WHERE username = ?", (u,))
        user_row = cursor.fetchone()

        if user_row and check_password_hash(user_row['password_hash'], p):
            session['username'] = u
            session['role'] = 'user'
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))

        flash('Неверный логин или пароль.', 'error')
        return render_template('login.html')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


# --- 4. Роуты менеджера паролей ---

@app.route('/')
@login_required
def index():
    username = session.get('username')
    return render_template('index.html', username=username)


@app.route('/generate', methods=['POST'])
@login_required
def generate():
    j = request.get_json() or {}

    try:
        L = int(j.get('length', 16))
    except:
        L = 16

    L = max(4, min(128, L))

    chars = ''
    if j.get('lowercase'):
        chars += 'abcdefghijklmnopqrstuvwxyz'
    if j.get('uppercase'):
        chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if j.get('numbers'):
        chars += '0123456789'
    if j.get('symbols'):
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'

    if not chars:
        return jsonify({'error': 'Выберите хотя бы один тип символов.'}), 400

    pwd = ''.join(random.choice(chars) for _ in range(L))

    site = j.get('site', '').strip()
    login = j.get('login', '').strip()

    username = session.get('username')
    user_id = get_user_id(username)

    if user_id:
        db = get_db()
        cursor = db.cursor()

        # Сохранение в таблице Passwords
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO Passwords (user_id, site, login_site, password_site, time) VALUES (?, ?, ?, ?, ?)",
            (user_id, site, login, pwd, timestamp)
        )
        db.commit()

    return jsonify({'password': pwd})


@app.route('/passwords')
@login_required
def passwords():
    username = session.get('username')
    user_id = get_user_id(username)

    if not user_id:
        return jsonify({'passwords': []})

    db = get_db()
    cursor = db.cursor()

    # Получаем ID, Сайт, Логин, Пароль и Время для текущего пользователя
    cursor.execute(
        "SELECT id, site, login_site, password_site, time FROM Passwords WHERE user_id = ? ORDER BY time DESC",
        (user_id,)
    )

    # Конвертируем Row-объекты в список словарей для JSON
    user_passwords = [dict(row) for row in cursor.fetchall()]

    # Переименовываем поля, чтобы соответствовать старому формату JSON (для минимальных изменений в HTML)
    # id -> id (PK)
    # login_site -> login
    # password_site -> password

    result_list = []
    for p in user_passwords:
        result_list.append({
            'id': p['id'],  # Это уникальный ID из БД, который будет использоваться для удаления
            'site': p['site'] or '—',
            'login': p['login_site'] or '—',
            'password': p['password_site'],
            'time': p['time']
        })

    return jsonify({'passwords': result_list})


@app.route('/delete_password', methods=['POST'])
@login_required
def delete_password():
    record_id = request.json.get('id')
    username = session.get('username')
    user_id = get_user_id(username)

    # Проверка: ID должен быть числом и пользователь должен существовать
    if user_id and isinstance(record_id, int):
        db = get_db()
        cursor = db.cursor()

        # Удаляем запись, проверяя, что она принадлежит текущему пользователю
        cursor.execute(
            "DELETE FROM Passwords WHERE id = ? AND user_id = ?",
            (record_id, user_id)
        )
        db.commit()

        if cursor.rowcount > 0:
            return jsonify({'status': 'ok'})

    return jsonify({'error': 'Invalid ID or Not found'}), 404


if __name__ == '__main__':
    # Инициализация базы данных при первом запуске
    with app.app_context():
        init_db()

    app.run(host='0.0.0.0', port=8080, debug=True)