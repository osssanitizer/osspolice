import unittest
from LexerOutputWrapper import callLexerOutput, callLexerOutputSubprocess

class CompatabilityTest(unittest.TestCase):
    def _test_helper(self, infile, expectedfile, filterTokenTypes=None):
        if filterTokenTypes:
            res = [line for line in callLexerOutput(infile=infile, filterTokenTypes=filterTokenTypes)]
        else:
            res = [line for line in callLexerOutput(infile=infile)]
        self.assertEqual('\n'.join(res) + '\n', open(expectedfile, 'r').read())

    def test_normal_c(self):
        self._test_helper(infile='testdata/example.c', expectedfile='testdata/example.out')

    def test_normal_c_filter(self):
        self._test_helper(infile='testdata/example.c', expectedfile='testdata/example.string_literal.out',
                          filterTokenTypes=['string_literal'])

    def test_header_c(self):
        self._test_helper(infile='testdata/html.h', expectedfile='testdata/html.out')

    def test_missing_include(self):
        self._test_helper(infile='testdata/pdf-form.c', expectedfile='testdata/pdf-form.out')

    def test_missing_include_filter(self):
        self._test_helper(infile='testdata/pdf-form.c', expectedfile='testdata/pdf-form.string_literal.out',
                          filterTokenTypes=['string_literal'])

    def test_missing_macro(self):
        self._test_helper(infile='testdata/pdf-font.c', expectedfile='testdata/pdf-font.out')

    def test_include_messing_ci_state(self):
        # Including the stdlib.h, seems to mess the lexer result of other files, i.e. the internal state of compiler
        # instance. Therefore, we want to make sure that this result is consistent.
        self._test_helper(infile='testdata/test-pp-directive-good.c', expectedfile='testdata/test-pp-directive-good.out')

    def test_branch_directive(self):
        # The both branch result (test-pp-directive.both_branch.txt) is under testing now.
        # Currently we don't include them.
        self._test_helper(infile='testdata/test-pp-directive.c', expectedfile='testdata/test-pp-directive.else.out')


if __name__ == "__main__":
    unittest.main()
