RESET = '\033[0m'  # Branco


def print_banner():
    padding = '  '

    C = [[' ', '┌', '─', '┐'], [' ', '│', ' ', ' '], [' ', '└', '─', '┘']]
    I = [[' ', ' ', '┬', ' '], [' ', ' ', '│', ' '], [' ', ' ', '┴', ' ']]
    N = [['┌', '┐', ' ', '┬'], ['│', '└', '┐', '│'], ['┴', ' ', '└', '┘']]
    E = [[' ', '┌', '─', '┐'], [' ', '├', '┤', ' '], [' ', '└', '─', '┘']]
    L = [[' ', '┬', ' ', ' '], [' ', '│', ' ', ' '], [' ', '┴', '─', '┘']]
    Ç = [[' ', ' ', ' ', ' '], [' ', ' ', ' ', ' '], [' ', ' ', ' ', ' ']]
    L = [[' ', '┬', ' ', ' '], [' ', '│', ' ', ' '], [' ', '┴', '─', '┘']]
    M = [['┌', '┐', '┌', '┐'], ['│', '└', '┘', '│'], ['┴', ' ', ' ', '┴']]
    T = [['─', '┬', '─', ' '], [' ', '│', ' ', ' '], [' ', '┴', ' ', ' ']]

    banner = [C, I, N, E, L, Ç, M, I, T, M]
    final = []
    print('\r')
    init_color = 36
    txt_color = init_color
    cl = 0

    for charset in range(0, 3):
        for pos in range(0, len(banner)):
            for i in range(0, len(banner[pos][charset])):
                clr = f'\033[38;5;{txt_color}m'
                char = f'{clr}{banner[pos][charset][i]}'
                final.append(char)
                cl += 1
                txt_color = txt_color + 36 if cl <= 3 else txt_color
            cl = 0
            txt_color = init_color
        init_color += 31

        if charset < 2:
            final.append('\n   ')

    print(f"   {''.join(final)}")
    print(f'{RESET}{padding}           ...por João Alonso\n')
