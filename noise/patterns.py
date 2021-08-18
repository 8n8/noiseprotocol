from noise.constants import TOKEN_S, TOKEN_E, TOKEN_ES, TOKEN_SS, TOKEN_EE, TOKEN_SE
from noise.functions.patterns import OneWayPattern, Pattern


# Interactive patterns

class PatternKK(Pattern):
    def __init__(self):
        super(PatternKK, self).__init__()
        self.name = 'KK'

        self.pre_messages = [
            [TOKEN_S],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES, TOKEN_SS],
            [TOKEN_E, TOKEN_EE, TOKEN_SE]
        ]
