/*
 * app_dea : configuration file tokenizer.
 */

%{
#include "app_dea.h"
/* Include yacc tokens definitions */
#include "dea_conf.tab.h"

/* Update the column information */
#define YY_USER_ACTION { 						\
	yylloc->first_column = yylloc->last_column + 1; 		\
	yylloc->last_column = yylloc->first_column + yyleng - 1;	\
}

/* Avoid warning with newer flex */
#define YY_NO_INPUT

%}

qstring		\"[^\"\n]*\"


%option bison-bridge bison-locations
%option noyywrap
%option nounput

%%

	/* Update the line count */
\n			{
				yylloc->first_line++;
				yylloc->last_line++;
				yylloc->last_column=0;
			}

	/* Eat all spaces but not new lines */
([[:space:]]{-}[\n])+	;
	/* Eat all comments */
#.*$			;

	/* Recognize any integer */
[[:digit:]]+		{
				/* Convert this to an u32 value */
				int ret=0;
				ret = sscanf(yytext, "%u", &yylval->u32);
				if (ret != 1) {
					/* No matching: an error occurred */
					fd_log_debug("Unable to convert the value '%s' to a valid number: %s", yytext, strerror(errno));
					return TOK_LEX_ERROR; /* trig an error in yacc parser */
				}
				return TOK_U32VAL;
			}

	/* Recognize quoted strings */
{qstring}		{
				/* Match a quoted string. */
				CHECK_MALLOC_DO( yylval->str = strdup(yytext+1),
				{
					TRACE_DEBUG(INFO, "Unable to copy the string '%s': %s", yytext, strerror(errno));
					return TOK_LEX_ERROR; /* trig an error in yacc parser */
				} );
				yylval->str[strlen(yytext) - 2] = '\0';
				return TOK_QSTRING;
			}

	/* The key words */
(?i:"hidden_identity")		{ return TOK_HIDDEN_IDENTITY;		}
(?i:"internal_realm")		{ return TOK_INTERNAL_REALM;		}
(?i:"hide_origin_host")	{ return TOK_HIDE_ORIGIN_HOST;		}
(?i:"hide_route_record")	{ return TOK_HIDE_ROUTE_RECORD;	}
(?i:"hide_session_id")		{ return TOK_HIDE_SESSION_ID;		}
(?i:"session_id_lifetime")	{ return TOK_SESSION_ID_LIFETIME;	}
(?i:"pseudonymize_subscriber_id")	{ return TOK_PSEUDONYMIZE_SUBSCRIBER_ID;	}
(?i:"imsi_pseudonym_key")	{ return TOK_IMSI_PSEUDONYM_KEY;	}
(?i:"interconnect_realm")	{ return TOK_INTERCONNECT_REALM;	}
(?i:"fraud_check_realm_consistency")	{ return TOK_FRAUD_CHECK_REALM_CONSISTENCY;	}
(?i:"fraud_reject_on_mismatch")	{ return TOK_FRAUD_REJECT_ON_MISMATCH;	}
(?i:"stats_interval")		{ return TOK_STATS_INTERVAL;		}
(?i:"discovered_peers_file")	{ return TOK_DISCOVERED_PEERS_FILE;	}
(?i:"pending_peer_add_file")	{ return TOK_PENDING_PEER_ADD_FILE;	}

	/* Valid single characters for yyparse */
[:=;]		{ return yytext[0]; }

	/* Unrecognized sequence, if it did not match any previous pattern */
[^[:space:]\":=;\n]+	{
				fd_log_debug("Unrecognized text on line %d col %d: '%s'.", yylloc->first_line, yylloc->first_column, yytext);
			 	return TOK_LEX_ERROR;
			}

%%
