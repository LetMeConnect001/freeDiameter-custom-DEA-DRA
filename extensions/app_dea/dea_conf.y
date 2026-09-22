/*
 * app_dea : configuration parser.
 * See doc/app_dea.conf.sample for the configuration file format.
 */

/* For development only : */
%debug
%error-verbose

/* The parser receives the configuration file filename as parameter */
%parse-param {char * conffile}

/* Keep track of location */
%locations
%pure-parser

%{
#include "app_dea.h"
#include "dea_conf.tab.h"	/* bison is not smart enough to define the YYLTYPE before including this code, so... */

/* Forward declaration */
int yyparse(char * conffile);

/* We initialize statically the config */
static struct dea_config local_conf = {
	.hidden_id = NULL,
	.hidden_id_len = 0,
	.internal_realms = FD_LIST_INITIALIZER(local_conf.internal_realms),
	.hide_origin_host = 1,
	.hide_route_record = 1,
	.hide_session_id = 0,		/* opt-in: deviates from RFC 6733 relay behavior, see README */
	.session_id_lifetime = 86400	/* 24h of inactivity before a Session-Id pairing expires */
};
struct dea_config * dea_conf = &local_conf;

/* Dump the configuration */
static void dea_conf_dump(void)
{
	struct fd_list * li;
	if (!TRACE_BOOL(FULL))
		return;

	fd_log_debug("app_dea: configuration dump:");
	fd_log_debug("   hidden_identity    : %s", dea_conf->hidden_id ? (char *)dea_conf->hidden_id : "(not set -- topology hiding DISABLED)");
	fd_log_debug("   hide_origin_host   : %s", dea_conf->hide_origin_host ? "yes" : "no");
	fd_log_debug("   hide_route_record  : %s", dea_conf->hide_route_record ? "yes" : "no");
	fd_log_debug("   hide_session_id    : %s", dea_conf->hide_session_id ? "yes" : "no");
	fd_log_debug("   session_id_lifetime: %u sec", dea_conf->session_id_lifetime);
	fd_log_debug("   internal realms:");
	for (li = dea_conf->internal_realms.next; li != &dea_conf->internal_realms; li = li->next) {
		struct dea_realm * r = li->o;
		fd_log_debug("     - %.*s", (int)r->len, r->name);
	}
	fd_log_debug("app_dea: end of configuration dump");
}

/* Parse the configuration file */
int dea_conf_handle(char * conffile)
{
	extern FILE * dea_confin;
	int ret;

	TRACE_ENTRY("%p", conffile);

	TRACE_DEBUG (FULL, "Parsing configuration file: %s...", conffile);

	dea_confin = fopen(conffile, "r");
	if (dea_confin == NULL) {
		ret = errno;
		TRACE_DEBUG(INFO, "Unable to open extension configuration file %s for reading: %s", conffile, strerror(ret));
		return ret;
	}

	ret = yyparse(conffile);

	fclose(dea_confin);

	if (ret != 0) {
		TRACE_DEBUG (INFO, "Unable to parse the configuration file.");
		return EINVAL;
	}

	if (!dea_conf->hidden_id) {
		fd_log_notice("app_dea: no 'hidden_identity' configured -- topology hiding is DISABLED, the extension will only pass messages through.");
	} else if (FD_IS_LIST_EMPTY(&dea_conf->internal_realms)) {
		fd_log_notice("app_dea: 'hidden_identity' is set but no 'internal_realm' configured -- topology hiding will never trigger.");
	}

	dea_conf_dump();

	return 0;
}

/* The Lex parser prototype */
int dea_conflex(YYSTYPE *lvalp, YYLTYPE *llocp);

/* Function to report the errors */
void yyerror (YYLTYPE *ploc, char * conffile, char const *s)
{
	TRACE_DEBUG(INFO, "Error in configuration parsing");

	if (ploc->first_line != ploc->last_line) {
		TRACE_DEBUG (INFO, "%s:%d.%d-%d.%d : %s", conffile, ploc->first_line, ploc->first_column, ploc->last_line, ploc->last_column, s);
	} else if (ploc->first_column != ploc->last_column) {
		TRACE_DEBUG (INFO, "%s:%d.%d-%d : %s", conffile, ploc->first_line, ploc->first_column, ploc->last_column, s);
	} else {
		TRACE_DEBUG (INFO, "%s:%d.%d : %s", conffile, ploc->first_line, ploc->first_column, s);
	}
}

%}

/* Values returned by lex for token */
%union {
	uint32_t	 u32;	/* Store integer / boolean values */
	char		*str;	/* Store a malloc'd string (must be freed after use, unless transferred to the config) */
}

/* In case of error in the lexical analysis */
%token 		TOK_LEX_ERROR

/* A quoted string (malloc'd in lex parser) */
%token <str> 	TOK_QSTRING

/* An integer / boolean value */
%token <u32> 	TOK_U32VAL

/* Tokens */
%token 		TOK_HIDDEN_IDENTITY
%token 		TOK_INTERNAL_REALM
%token 		TOK_HIDE_ORIGIN_HOST
%token 		TOK_HIDE_ROUTE_RECORD
%token 		TOK_HIDE_SESSION_ID
%token 		TOK_SESSION_ID_LIFETIME


/* -------------------------------------- */
%%

	/* The grammar definition */
conffile:		/* empty grammar is OK */
			| conffile directive
			;

directive:		TOK_HIDDEN_IDENTITY '=' TOK_QSTRING ';'
			{
				if (dea_conf->hidden_id) {
					free($3);
					yyerror (&yylloc, conffile, "hidden_identity can only be specified once.");
					YYERROR;
				}
				if (!fd_os_is_valid_DiameterIdentity((uint8_t *)$3, strlen($3))) {
					free($3);
					yyerror (&yylloc, conffile, "hidden_identity is not a valid Diameter Identity.");
					YYERROR;
				}
				dea_conf->hidden_id = (os0_t) $3;
				dea_conf->hidden_id_len = strlen($3);
			}
			|
			TOK_INTERNAL_REALM '=' TOK_QSTRING ';'
			{
				struct dea_realm * r;
				CHECK_MALLOC_DO( r = malloc(sizeof(struct dea_realm)),
					{
						free($3);
						yyerror (&yylloc, conffile, "Error while allocating new memory...");
						YYERROR;
					} );
				memset(r, 0, sizeof(struct dea_realm));
				fd_list_init(&r->chain, r);
				r->name = (os0_t) $3;
				r->len = strlen($3);
				fd_list_insert_before(&dea_conf->internal_realms, &r->chain);
			}
			|
			TOK_HIDE_ORIGIN_HOST '=' TOK_U32VAL ';'
			{
				dea_conf->hide_origin_host = $3 ? 1 : 0;
			}
			|
			TOK_HIDE_ROUTE_RECORD '=' TOK_U32VAL ';'
			{
				dea_conf->hide_route_record = $3 ? 1 : 0;
			}
			|
			TOK_HIDE_SESSION_ID '=' TOK_U32VAL ';'
			{
				dea_conf->hide_session_id = $3 ? 1 : 0;
			}
			|
			TOK_SESSION_ID_LIFETIME '=' TOK_U32VAL ';'
			{
				dea_conf->session_id_lifetime = $3;
			}
			;

%%
