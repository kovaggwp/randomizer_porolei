from flask import Flask, render_template, request, redirect, url_for, session
import random
import string
from functools import wraps

app = Flask(__name__)
# !!! Обязательно установите секретный ключ для работы сессий !!!
app.secret_key = 'your_strong_and_unique_secret_key'

# Локальные учетные данные для авторизации (замените на свои!)
USER_CREDENTIALS = {
    "user": "securepassword"
}


# --- Декоратор для проверки авторизации ---
def login_required(f):
    """Декоратор, который перенаправляет неавторизованных пользователей на страницу входа."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # Перенаправляем на страницу входа, сохраняя URL, который хотел посетить пользователь
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# --- Логика генерации пароля (без изменений) ---
def generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols):
    # ... (Ваша функция генерации пароля) ...
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

    # Убедитесь, что длина не превышает доступные символы, хотя это маловероятно
    length = max(4, min(length, 128))

    password = ''.join(random.choice(characters) for i in range(length))
    return password


# --- Маршруты приложения ---

@app.route('/', methods=['GET', 'POST'])
@login_required  # Защищаем маршрут генератора паролей
def index():
    password = None
    # Получаем имя пользователя из сессии для отображения
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

    return render_template(
        'index.html',
        password=password,
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        username=username  # Передаем имя пользователя
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            session['logged_in'] = True
            session['username'] = username

            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        else:
            error = 'Неправильный логин или пароль.'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)