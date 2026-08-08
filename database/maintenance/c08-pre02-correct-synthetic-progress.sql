\set ON_ERROR_STOP on

BEGIN ISOLATION LEVEL SERIALIZABLE;

SET LOCAL search_path = pg_catalog, public;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

LOCK TABLE public.intelligence_sources IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.ingestion_runs IN SHARE MODE;

DO $c08_pre02_preconditions$
DECLARE
    expected_revision constant text := 'f8d739439ed0';
    expected_checkpoint_sha256 constant text :=
        '1c4f57ad3b27a40b2157dd0fade25a74363f889b8a1972702e2eb9570c2c9fa4';
    version_row_count integer;
    current_revision text;
    target_row_count integer;
    exact_slug_count integer;
    valid_checkpoint_count integer;
    null_timestamp_count integer;
    associated_run_count integer;
    successful_run_count integer;
    running_run_count integer;
    matching_correlation_count integer;
    extra_shape_count integer;
BEGIN
    IF current_database() <> 'alpha_data_db' THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected database';
    END IF;
    IF current_user <> 'alpha_data_user' THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected correction identity';
    END IF;

    SELECT count(*), min(version_num)
    INTO version_row_count, current_revision
    FROM public.alembic_version;

    IF version_row_count <> 1 OR current_revision IS DISTINCT FROM expected_revision THEN
        RAISE EXCEPTION 'C08-PRE-02 revision precondition failed';
    END IF;

    WITH target_slugs(slug) AS (
        VALUES
            ('alpha-synthetic-cve'),
            ('alpha-synthetic-advisories'),
            ('alpha-synthetic-news'),
            ('alpha-synthetic-uae')
    ), target_rows AS (
        SELECT source.id, source.slug, source.checkpoint_value,
               source.last_successful_fetch_at
        FROM public.intelligence_sources AS source
        JOIN target_slugs ON target_slugs.slug = source.slug
    )
    SELECT
        count(*),
        count(DISTINCT slug),
        count(*) FILTER (
            WHERE checkpoint_value IS NOT NULL
              AND encode(sha256(convert_to(checkpoint_value, 'UTF8')), 'hex')
                  = expected_checkpoint_sha256
        ),
        count(*) FILTER (WHERE last_successful_fetch_at IS NULL)
    INTO target_row_count, exact_slug_count, valid_checkpoint_count,
         null_timestamp_count
    FROM target_rows;

    IF target_row_count <> 4 OR exact_slug_count <> 4 THEN
        RAISE EXCEPTION 'C08-PRE-02 exact target-row precondition failed';
    END IF;
    IF valid_checkpoint_count <> 4 OR null_timestamp_count <> 4 THEN
        RAISE EXCEPTION 'C08-PRE-02 synthetic progress shape precondition failed';
    END IF;

    WITH target_slugs(slug) AS (
        VALUES
            ('alpha-synthetic-cve'),
            ('alpha-synthetic-advisories'),
            ('alpha-synthetic-news'),
            ('alpha-synthetic-uae')
    )
    SELECT
        count(run.id),
        count(run.id) FILTER (WHERE run.status IN ('success', 'succeeded')),
        count(run.id) FILTER (WHERE run.status = 'running'),
        count(run.id) FILTER (
            WHERE run.status IN ('success', 'succeeded')
              AND run.completed_at = source.last_successful_fetch_at
              AND run.checkpoint_after = source.checkpoint_value
        )
    INTO associated_run_count, successful_run_count, running_run_count,
         matching_correlation_count
    FROM public.intelligence_sources AS source
    JOIN target_slugs ON target_slugs.slug = source.slug
    LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id;

    IF associated_run_count <> 0
       OR successful_run_count <> 0
       OR running_run_count <> 0
       OR matching_correlation_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 target run-history precondition failed';
    END IF;

    WITH target_slugs(slug) AS (
        VALUES
            ('alpha-synthetic-cve'),
            ('alpha-synthetic-advisories'),
            ('alpha-synthetic-news'),
            ('alpha-synthetic-uae')
    )
    SELECT count(*)
    INTO extra_shape_count
    FROM public.intelligence_sources AS source
    WHERE NOT EXISTS (
        SELECT 1 FROM target_slugs WHERE target_slugs.slug = source.slug
    )
      AND source.checkpoint_value IS NOT NULL
      AND source.last_successful_fetch_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM public.ingestion_runs AS run
          WHERE run.source_id = source.id
      );

    IF extra_shape_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 unexpected non-target correction shape found';
    END IF;
END
$c08_pre02_preconditions$;

WITH target_slugs(slug) AS (
    VALUES
        ('alpha-synthetic-cve'),
        ('alpha-synthetic-advisories'),
        ('alpha-synthetic-news'),
        ('alpha-synthetic-uae')
)
SELECT
    'before' AS verification_phase,
    count(*) AS target_count,
    bool_and(source.checkpoint_value IS NOT NULL) AS checkpoints_present,
    bool_and(source.last_successful_fetch_at IS NULL) AS timestamps_null,
    string_agg(
        encode(sha256(convert_to(source.id::text, 'UTF8')), 'hex'),
        ',' ORDER BY source.slug
    ) AS sanitized_id_fingerprints
FROM public.intelligence_sources AS source
JOIN target_slugs ON target_slugs.slug = source.slug;

DO $c08_pre02_update$
DECLARE
    affected_row_count integer;
BEGIN
    WITH target_slugs(slug) AS (
        VALUES
            ('alpha-synthetic-cve'),
            ('alpha-synthetic-advisories'),
            ('alpha-synthetic-news'),
            ('alpha-synthetic-uae')
    )
    UPDATE public.intelligence_sources AS source
    SET checkpoint_value = NULL
    FROM target_slugs
    WHERE source.slug = target_slugs.slug
      AND source.checkpoint_value IS NOT NULL
      AND source.last_successful_fetch_at IS NULL;

    GET DIAGNOSTICS affected_row_count = ROW_COUNT;
    IF affected_row_count <> 4 THEN
        RAISE EXCEPTION 'C08-PRE-02 affected-row verification failed';
    END IF;
END
$c08_pre02_update$;

WITH target_slugs(slug) AS (
    VALUES
        ('alpha-synthetic-cve'),
        ('alpha-synthetic-advisories'),
        ('alpha-synthetic-news'),
        ('alpha-synthetic-uae')
)
SELECT
    'after' AS verification_phase,
    count(*) AS target_count,
    bool_and(source.checkpoint_value IS NULL) AS checkpoints_null,
    bool_and(source.last_successful_fetch_at IS NULL) AS timestamps_still_null,
    count(run.id) AS associated_run_count,
    string_agg(
        encode(sha256(convert_to(source.id::text, 'UTF8')), 'hex'),
        ',' ORDER BY source.slug
    ) AS sanitized_id_fingerprints
FROM public.intelligence_sources AS source
JOIN target_slugs ON target_slugs.slug = source.slug
LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id;

DO $c08_pre02_postconditions$
DECLARE
    remaining_checkpoint_count integer;
    nonnull_timestamp_count integer;
    associated_run_count integer;
BEGIN
    WITH target_slugs(slug) AS (
        VALUES
            ('alpha-synthetic-cve'),
            ('alpha-synthetic-advisories'),
            ('alpha-synthetic-news'),
            ('alpha-synthetic-uae')
    )
    SELECT
        count(*) FILTER (WHERE source.checkpoint_value IS NOT NULL),
        count(*) FILTER (WHERE source.last_successful_fetch_at IS NOT NULL),
        count(run.id)
    INTO remaining_checkpoint_count, nonnull_timestamp_count,
         associated_run_count
    FROM public.intelligence_sources AS source
    JOIN target_slugs ON target_slugs.slug = source.slug
    LEFT JOIN public.ingestion_runs AS run ON run.source_id = source.id;

    IF remaining_checkpoint_count <> 0
       OR nonnull_timestamp_count <> 0
       OR associated_run_count <> 0 THEN
        RAISE EXCEPTION 'C08-PRE-02 postcondition failed';
    END IF;
END
$c08_pre02_postconditions$;

COMMIT;
