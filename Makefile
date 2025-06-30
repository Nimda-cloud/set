# NIMDA Security System Makefile

.PHONY: help install test clean run demo lint format

help:  ## Показати допомогу
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Встановити залежності
	pip3 install -r requirements.txt

test:  ## Запустити тести
	python3 -m pytest tests/ -v

clean:  ## Очистити тимчасові файли
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete

run:  ## Запустити головний інтерфейс
	python3 nimda_tkinter.py

demo:  ## Запустити демонстрацію
	python3 demos/nimda_complete_demo.py

lint:  ## Перевірити код
	python3 -m flake8 . --max-line-length=100 --exclude=__pycache__,venv

format:  ## Форматувати код
	python3 -m black . --line-length=100

setup:  ## Встановити пакет для розробки
	pip3 install -e .

dist:  ## Створити дистрибутив
	python3 setup.py sdist bdist_wheel

upload:  ## Завантажити до PyPI (тестовий)
	python3 -m twine upload --repository testpypi dist/*

reorganize:  ## Реорганізувати структуру проекту
	python3 reorganize_project.py
