from flask import Flask, render_template, request
import random
import string

app = Flask(__name__)


def generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols):
    """Генерирует пароль на основе указанных критериев."""
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

    password = ''.join(random.choice(characters) for i in range(length))
    return password


@app.route('/', methods=['GET', 'POST'])
def index():
    password = None
    # Устанавливаем значения по умолчанию для первого захода на страницу
    length = 12
    use_lowercase = True
    use_uppercase = True
    use_digits = True
    use_symbols = False

    if request.method == 'POST':
        try:
            # Получаем значения из формы
            length = int(request.form.get('length'))
            use_lowercase = 'lowercase' in request.form
            use_uppercase = 'uppercase' in request.form
            use_digits = 'digits' in request.form
            use_symbols = 'symbols' in request.form

            password = generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols)
        except (ValueError, TypeError):
            password = "Ошибка: пожалуйста, введите действительную длину."

    # Передаем текущие значения (из формы или по умолчанию) в шаблон
    return render_template(
        'index.html',
        password=password,
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols
    )


if __name__ == '__main__':
    app.run(debug=True)