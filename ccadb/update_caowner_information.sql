\timing

\echo Importing All CCADB CA Owner Records

BEGIN WORK;

LOCK ccadb_caowner;

TRUNCATE ccadb_caowner;

\COPY ccadb_caowner FROM 'ccadb_caowner_information.csv' CSV HEADER;

COMMIT WORK;
