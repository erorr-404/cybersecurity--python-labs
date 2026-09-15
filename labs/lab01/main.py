from labs.lab01 import task1
from labs.lab01 import task2
from labs.lab01 import task3
from rich.console import Console

if __name__ == "__main__":
    c = Console()
    
    c.rule()
    c.print("Результат виконання лабораторної роботи", justify="center", style="bold")
    
    c.print("Завдання 1", justify="center", style="italic")
    task1.main()
    
    c.rule()
    c.print("Завдання 2", justify="center", style="italic")
    task2.main()
    
    c.rule()
    c.print("Завдання 3", justify="center", style="italic")
    task3.main()
    
    c.print("Виконання завершено", justify="center")
    c.rule()