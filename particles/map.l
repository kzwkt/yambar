%{
#include <string.h>
#include "map.h"
#include "map.tab.h"
void yyerror(const char *s);
%}

%option warn nodefault nounput noinput noyywrap

 char *quoted = NULL;
 size_t quote_len = 0;

%x QUOTE

%%

[[:alnum:]_-]+          yylval.str = strdup(yytext); return WORD;

\" {
  BEGIN(QUOTE);
  quoted = calloc(1, sizeof(quoted[0]));
}

<QUOTE>[^\\\"]* {
  /* printf("CAT: %s\n", yytext); */
  const size_t yy_length = strlen(yytext);
  quoted = realloc(quoted, quote_len + yy_length + 1);
  strcat(quoted, yytext);
  quote_len += yy_length;
}

<QUOTE>\\\" {
  /* printf("escaped quote\n"); */
  quoted = realloc(quoted, quote_len + 1 + 1);
  strcat(quoted, "\"");
  quote_len++;
}

<QUOTE>\\. {
  /* printf("CAT: %s\n", yytext); */
  const size_t yy_length = strlen(yytext);
  quoted = realloc(quoted, quote_len + yy_length + 1);
  strcat(quoted, yytext);
  quote_len += yy_length;
}

<QUOTE>\\ {
  /* quoted string that ends with a backslash: "string\ */
  quoted = realloc(quoted, quote_len + 1 + 1);
  strcat(quoted, "\\");
  quote_len++;
}

<QUOTE>\" {
  /* printf("QUOTED=%s\n", quoted); */
  yylval.str = strdup(quoted);

  free(quoted);
  quoted = NULL;
  quote_len = 0;

  BEGIN(INITIAL);
  return STRING;
}

==                      yylval.op = MAP_OP_EQ; return CMP_OP;
!=                      yylval.op = MAP_OP_NE; return CMP_OP;
\<=                     yylval.op = MAP_OP_LE; return CMP_OP;
\<                      yylval.op = MAP_OP_LT; return CMP_OP;
>=                      yylval.op = MAP_OP_GE; return CMP_OP;
>                       yylval.op = MAP_OP_GT; return CMP_OP;
&&                      yylval.op = MAP_OP_AND; return BOOL_OP;
\|\|                    yylval.op = MAP_OP_OR; return BOOL_OP;
~                       return NOT;
\(                      return L_PAR;
\)                      return R_PAR;
[ \t\n]                 ;
.                       yylval.str = strdup(yytext); return STRING;
%%
