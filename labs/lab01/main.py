from rich.console import Console

from labs.lab01 import task1, task2, task3

if __name__ == "__main__":
    c = Console()

    c.print("Результат виконання лабораторної роботи", justify="center", style="bold")

    c.rule("Завдання 1", style="italic")
    task1.main()

    c.rule("Завдання 2", style="italic")
    task2.main()

    c.rule("Завдання 3", style="italic")
    task3.main()

    c.rule("Виконання завершено")
