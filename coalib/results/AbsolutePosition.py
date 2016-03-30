from coalib.results.TextPosition import TextPosition
from coalib.misc.Decorators import enforce_signature


class AbsolutePosition(TextPosition):

    @enforce_signature
    def __init__(self,
                 text: (tuple, list, None)=None,
                 position: (int, None)=None):
        """
        Creates an AbsolutePosition object that represents the index of a
        character in a string.

        :param text:     The text containing the character.
        :param position: Position identifying the index of character
                         in text.
        """
        line = column = None
        if position and text:
            line, column = calc_line_col(text, position)
        self._text = text
        self._position = position
        super(AbsolutePosition, self).__init__(line, column)

    @property
    def position(self):
        return self._position


def calc_line_col(text, pos_to_find):
    """
    Creates a tuple containing (line, column) by calculating line number
    and column in the text, from position. Uses \\n as the newline
    character. Line and column start from 1.

    :param text:          A tuple/list of lines in which position is to
                          be calculated.
    :param pos_to_find:   Position of character to be found in the
                          (line, column) form.
    :return:              A tuple of the form (line, column).
    """
    line = 1
    position = pos_to_find
    while True:
        try:
            textline = text[line - 1]
        except IndexError:
            raise ValueError("Position not found in text")
        new_position = position - len(textline)
        if new_position < 0:
            break
        line += 1
        position = new_position
    col = position + 1
    return (line, col)
