def square_root_of_quadratic_residue(n, modulo):
    """Square root of quadratic residue

    Solve the square root of quadratic residue using Cipolla's algorithm with Legendre symbol
    Returns:
        int -- if n is a quadratic residue,
                   return x, such that x^{2} = n (mod modulo)
               otherwise, return -1
    """
    if modulo == 2:
        return 1
    if n % modulo == 0:
        return 0
    Legendre = lambda n: pow(n, modulo - 1 >> 1, modulo)
    if Legendre(n) == modulo - 1:
        return -1
    t = 0
    while Legendre(t ** 2 - n) != modulo - 1:
        t += 1
    w = (t ** 2 - n) % modulo
    return (generate_quadratic_field(w, modulo)(t, 1) ** (modulo + 1 >> 1)).x


def generate_quadratic_field(d, modulo=0):
    """Generate quadratic field number class

        Returns:
            class -- quadratic field number class
    """

    assert (isinstance(modulo, int) and modulo >= 0)

    class QuadraticFieldNumber:
        def __init__(self, x, y):
            self.x = x % modulo
            self.y = y % modulo

        def __mul__(self, another):
            x = self.x * another.x + d * self.y * another.y
            y = self.x * another.y + self.y * another.x
            return self.__class__(x, y)

        def __pow__(self, exponent):
            result = self.__class__(1, 0)
            if exponent:
                temporary = self.__class__(self.x, self.y)
                while exponent:
                    if exponent & 1:
                        result *= temporary
                    temporary *= temporary
                    exponent >>= 1
            return result

        def __str__(self):
            return '({}, {} \\sqrt({}))'.format(self.x, self.y, d)

    return QuadraticFieldNumber


# pow(7,2,11) = 5

print(square_root_of_quadratic_residue(5, 11))
