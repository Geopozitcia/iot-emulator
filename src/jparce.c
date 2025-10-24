#include <ctype.h>
#include <jparce.h>
#include <string.h>
#include <unistd.h>

typedef enum
{
  LB,
  RB,
  STR,
  NUM,
  COMMA,
  MARK,
  COLON,
  ARRAY,
  LBS, /*square bracket*/
  RBS
} token_type;

typedef struct
{
  token_type type;
  char *value;
  size_t length;
} token_t;

typedef enum
{
  POS_KEY,
  POS_COLON,
  POS_VALUE,
  POS_COMMA
} pos_num;

int getToken (char *pos, token_t *token);
int getTokenType (char *pos);
int getStringToken (char *pos, token_t *token);
int getArrayToken (char *pos, token_t *token);
int getNumToken (char *pos, token_t *token);

int
getTokenType (char *pos)
{
  if (pos == NULL)
    {
      return -1;
    }
  if (*pos == '{')
    {
      return LB;
    }
  else if (*pos == '}')
    {
      return RB;
    }
  else if (*pos == ',')
    {
      return COMMA;
    }
  else if (*pos == '"')
    {
      return MARK;
    }
  else if (*pos == ':')
    {
      return COLON;
    }
  else if (*pos == '[')
    {
      return LBS;
    }
  else if (*pos == ']')
    {
      return RBS;
    }
  else if (isdigit (*pos))
    {
      return NUM;
    }
  else if (isalpha (*pos))
    {
      return STR;
    }
  return -1;
}

int
getStringToken (char *pos, token_t *token)
{
  if (pos == NULL)
    {
      return -1;
    }
  if (*pos != '"')
    {
      return -1;
    }
  int length = 1;
  pos++;
  while (*pos != '"' && *pos != '\0')
    {
      length++;
      pos++;
    }
  if (*pos == '"')
    {
      length++;
      token->length = length;
      token->type = STR;
      return 0;
    }
  else
    {
      return -1;
    }
  return 1;
}

int
getArrayToken (char *pos, token_t *token)
{
  char *firstPos = pos;
  token->value = pos;
  if (getTokenType (pos + 1) == RBS)
    {
      token->length = 2;
      token->type = ARRAY;
      return 0;
    }

  pos++;
  token_t argsToken;
  if (getToken (pos, &argsToken))
    {
      return -1;
    }

  int logPos = POS_VALUE;

  while (argsToken.type != RBS)
    {
      if (logPos == POS_VALUE)
        {
          if (!(argsToken.type == STR || argsToken.type == NUM
                || argsToken.type == ARRAY))
            {
              return -1;
            }
          logPos = POS_COMMA;
        }
      else if (logPos == POS_COMMA)
        {
          if (!(argsToken.type == COMMA))
            {
              return -1;
            }
          logPos = POS_VALUE;
        }
      if (getToken (argsToken.value + argsToken.length, &argsToken))
        {
          return -1;
        }
    }
  if (argsToken.type == RBS)
    {
      token->length = argsToken.value - firstPos + 1;
      token->type = ARRAY;
      return 0;
    }
  return -1;
}

int
getNumToken (char *pos, token_t *token)
{
  if (pos == NULL)
    {
      return -1;
    }
  if (!isdigit (*pos))
    {
      return -1;
    }
  int length = 1;
  pos++;

  int dotCount = 0;

  while (isdigit (*pos) || (*pos) == '.')
    {
      if (*pos == '.')
        {
          dotCount++;
        }
      length++;
      pos++;
      if (dotCount > 1)
        {
          return -1;
        }
    }
  if (isdigit (*(pos - 1)))
    {
      token->length = length;
      token->type = NUM;
      return 0;
    }
  return -1;
}

int
getToken (char *pos, token_t *token)
{
  while (*pos == ' ' || *pos == '\n')
    {
      pos++;
    }
  token->value = pos;
  token->length = 1;

  if (getTokenType (pos) == LB)
    {
      token->type = LB;
      return 0;
    }
  else if (getTokenType (pos) == RB)
    {
      token->type = RB;
      return 0;
    }
  else if (getTokenType (pos) == COLON)
    {
      token->type = COLON;
      return 0;
    }
  else if (getTokenType (pos) == COMMA)
    {
      token->type = COMMA;
      return 0;
    }
  else if (getTokenType (pos) == MARK)
    {
      getStringToken (pos, token);
      return 0;
    }
  else if (getTokenType (pos) == NUM)
    {
      getNumToken (pos, token);
      return 0;
    }
  else if (getTokenType (pos) == LBS)
    {
      if (getArrayToken (pos, token))
        {
          return -1;
        }
      return 0;
    }
  else if (getTokenType (pos) == RBS)
    {
      token->type = RBS;
      return 0;
    }
  return -1;
}

/*
Парсит json файл, проверяет его на валидность
возвращаемые зшначения: 0 - успех, иначе ошибка
*/
int
parse (char *str)
{
  if (str == NULL)
    {
      return -1;
    }

  char *pos = str;
  token_t token;
  if (getToken (pos, &token))
    {
      return -1;
    }

  if (token.type != LB)
    {
      return -1;
    }
  pos += token.length;

  char logPos = POS_KEY; /*in key : value , 0-key, 1-:, 2-value, 3-,*/
  int correctToken = getToken (pos, &token);

  if (token.type == RB)
    { /*обработка пустого json*/
      return 0;
    }

  while (!correctToken)
    {
      if (logPos == POS_KEY)
        {
          if (!(token.type == STR))
            {
              return -1; /*ошибка синтаксиса*/
            }
          logPos = POS_COLON;
        }
      else if (logPos == POS_COLON)
        {
          if (!(token.type == COLON))
            {
              return -1;
            }
          logPos = POS_VALUE;
        }
      else if (logPos == POS_VALUE)
        {
          if (!(token.type == STR || token.type == NUM || token.type == ARRAY))
            {
              return -1;
            }
          logPos = POS_COMMA;
        }
      else if (logPos == POS_COMMA)
        {
          if (!(token.type == RB || token.type == COMMA))
            {
              return -1;
            }
          if (token.type == RB)
            {
              break;
            }
          logPos = POS_KEY;
        }
      pos = token.value + token.length;
      correctToken = getToken (pos, &token);
    }
  if (correctToken)
    {
      return -1;
    }
  return 0;
}

/*
По ключу возвращает данные, помещает их в строку
*/

int
jGetVal (char *const json, char *const key, char *const dst)
{
  if (key == NULL)
    {
      return -1;
    }
  token_t token;
  getToken (json, &token); /*пропускаем открывающую скобку*/
  getToken (token.value + token.length, &token);

  int logPos = POS_KEY;
  while (token.type != RB)
    {
      if (logPos == POS_KEY)
        {
          char *keyStr
              = token.value + 1; /*+1 для того чтобы избавится от символа "*/
          int keyLen
              = token.length - 2; /*т.к мы избавляемся от 2 символов ""*/
          if (!strncmp (keyStr, key, keyLen))
            {
              getToken (token.value + token.length,
                        &token); /*получаем токен :*/
              getToken (token.value + token.length,
                        &token); /*получаем требуемый токен*/
              if (token.type == STR)
                {
                  /*в этом случае избавляемся от ""*/
                  strncpy (dst, token.value + 1, token.length - 2);
                  dst[token.length - 2] = '\0';
                }
              else
                {
                  strncpy (dst, token.value, token.length);
                  dst[token.length] = '\0';
                }
              return 0;
            }
          logPos = POS_COLON;
        }
      else if (logPos == POS_COLON)
        {
          logPos = POS_VALUE;
        }
      else if (logPos == POS_VALUE)
        {
          logPos = POS_COMMA;
        }
      else if (logPos == POS_COMMA)
        {
          logPos = POS_KEY;
        }
      getToken (token.value + token.length, &token);
    }
  return 1;
}
