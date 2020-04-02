\timing on

\set ON_ERROR_STOP on

CLUSTER VERBOSE ct_log;
--REINDEX TABLE ct_log;

CLUSTER VERBOSE ca;
--REINDEX TABLE ca;

CLUSTER VERBOSE ocsp_responder;
--REINDEX TABLE ocsp_responder;

CLUSTER VERBOSE crl;
--REINDEX TABLE crl;
