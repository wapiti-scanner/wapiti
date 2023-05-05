<?php
/**
 * Provides an interface for easily building a complex search query that
 * combines multiple ranking signals.
 *
 * $bldr = new Query_Builder();
 * $bldr->add_filter( ... );
 * $bldr->add_filter( ... );
 * $bldr->add_query( ... );
 * $es_query = $bldr->build_query();
 *
 *
 * All ES queries take a standard form with main query (with some filters),
 *  wrapped in a function_score
 *
 * Most functions are chainable, e.g. $bldr->add_filter( ... )->add_query( ... )->build_query();
 *
 * Bucketed queries use an aggregation to diversify results. eg a bunch
 *  of separate filters where to get different sets of results.
 *
 * @package    automattic/jetpack-search
 */

// Disables comment checks.
// phpcs:disable Squiz.Commenting

namespace Automattic\Jetpack\Search\WPES;

/**
 * Query builder class.
 */
class Query_Builder {
	/**
	 * ElasticSerach filters.
	 *
	 * @var array
	 */
	protected $es_filters = array();

	//
	// Variables for handling custom boosting with function_score.
	//
	protected $functions            = array();
	protected $weighting_functions  = array();
	protected $decays               = array();
	protected $scripts              = array();
	protected $functions_max_boost  = 2.0;
	protected $functions_score_mode = 'multiply';
	protected $functions_boost_mode = 'multiply';
	protected $query_bool_boost     = null;

	//
	// General aggregations for buckets and metrics.
	//
	protected $aggs_query = false;
	protected $aggs       = array();

	//
	// The set of top level text queries to combine.
	//
	protected $must_queries    = array();
	protected $should_queries  = array();
	protected $dis_max_queries = array();

	protected $diverse_buckets_query = false;
	protected $bucket_filters        = array();
	protected $bucket_sub_aggs       = array();

	public function get_langs() {
		if ( isset( $this->langs ) ) {
			return $this->langs;
		}
		return false;
	}

	//
	// Methods for building a query.
	//
	public function add_filter( $filter ) {
		$this->es_filters[] = $filter;

		return $this;
	}

	public function add_query( $query, $type = 'must' ) {
		switch ( $type ) {
			case 'dis_max':
				$this->dis_max_queries[] = $query;
				break;

			case 'should':
				$this->should_queries[] = $query;
				break;

			case 'must':
			default:
				$this->must_queries[] = $query;
				break;
		}

		return $this;
	}

	/**
	 * Add any weighting function to the query
	 *
	 * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-function-score-query.html
	 *
	 * @param $function array A function structure to apply to the query
	 *
	 * @return void
	 */
	public function add_weighting_function( $function ) {
		// check for danger.
		if ( isset( $function['random_score'] ) ) {
			return $this;
		}
		if ( isset( $function['script_score'] ) ) {
			return $this;
		}

		$this->weighting_functions[] = $function;

		return $this;
	}

	/**
	 * Add a scoring function to the query
	 *
	 * NOTE: For decays (linear, exp, or gauss), use Query_Builder::add_decay() instead
	 *
	 * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-function-score-query.html
	 *
	 * @param $function string name of the function
	 * @param $params array functions parameters
	 *
	 * @return void
	 */
	public function add_function( $function, $params ) {
		$this->functions[ $function ][] = $params;

		return $this;
	}

	/**
	 * Add a decay function to score results
	 *
	 * This method should be used instead of Query_Builder::add_function() for decays, as the internal  ES structure
	 * is slightly different for them.
	 *
	 * @see https://www.elastic.co/guide/en/elasticsearch/guide/current/decay-functions.html
	 *
	 * @param $function string name of the decay function - linear, exp, or gauss
	 * @param $params array The decay functions parameters, passed to ES directly
	 *
	 * @return void
	 */
	public function add_decay( $function, $params ) {
		$this->decays[ $function ][] = $params;

		return $this;
	}

	/**
	 * Add a scoring mode to the query
	 *
	 * @see https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-function-score-query.html
	 *
	 * @param $mode string name of how to score
	 *
	 * @return void
	 */
	public function add_score_mode_to_functions( $mode = 'multiply' ) {
		$this->functions_score_mode = $mode;

		return $this;
	}

	public function add_boost_mode_to_functions( $mode = 'multiply' ) {
		$this->functions_boost_mode = $mode;

		return $this;
	}

	public function add_max_boost_to_functions( $boost ) {
		$this->functions_max_boost = $boost;

		return $this;
	}

	public function add_boost_to_query_bool( $boost ) {
		$this->query_bool_boost = $boost;

		return $this;
	}

	public function add_aggs( $aggs_name, $aggs ) {
		$this->aggs_query         = true;
		$this->aggs[ $aggs_name ] = $aggs;

		return $this;
	}

	public function set_all_aggs( $aggs ) {
		$this->aggs_query = true;
		$this->aggs       = $aggs;

		return $this;
	}

	public function add_aggs_sub_aggs( $aggs_name, $sub_aggs ) {
		if ( ! array_key_exists( 'aggs', $this->aggs[ $aggs_name ] ) ) {
			$this->aggs[ $aggs_name ]['aggs'] = array();
		}
		$this->aggs[ $aggs_name ]['aggs'] = $sub_aggs;

		return $this;
	}

	public function add_bucketed_query( $name, $query ) {
		$this->add_bucket_filter( $name, $query );

		$this->add_query( $query, 'dis_max' );

		return $this;
	}

	public function add_bucketed_terms( $name, $field, $terms, $boost = 1 ) {
		if ( ! is_array( $terms ) ) {
			$terms = array( $terms );
		}

		$this->add_bucket_filter(
			$name,
			array(
				'terms' => array(
					$field => $terms,
				),
			)
		);

		$this->add_query(
			array(
				'constant_score' => array(
					'filter' => array(
						'terms' => array(
							$field => $terms,
						),
					),
					'boost'  => $boost,
				),
			),
			'dis_max'
		);

		return $this;
	}

	public function add_bucket_sub_aggs( $agg ) {
		$this->bucket_sub_aggs = array_merge( $this->bucket_sub_aggs, $agg );

		return $this;
	}

	protected function add_bucket_filter( $name, $filter ) {
		$this->diverse_buckets_query   = true;
		$this->bucket_filters[ $name ] = $filter;
	}

	////////////////////////////////////
	// Building Final Query

	/**
	 * Combine all the queries, functions, decays, scripts, and max_boost into an ES query
	 *
	 * @return array Array representation of the built ES query
	 */
	public function build_query() {
		$query = array();

		//dis_max queries just become a single must query
		if ( ! empty( $this->dis_max_queries ) ) {
			$this->must_queries[] = array(
				'dis_max' => array(
					'queries' => $this->dis_max_queries,
				),
			);
		}

		if ( empty( $this->must_queries ) ) {
			$this->must_queries = array(
				array(
					'match_all' => array(),
				),
			);
		}

		if ( empty( $this->should_queries ) ) {
			$query = array(
				'bool' => array(
					'must' => $this->must_queries,
				),
			);
		} else {
			$query = array(
				'bool' => array(
					'must'   => $this->must_queries,
					'should' => $this->should_queries,
				),
			);
		}

		if ( $this->query_bool_boost !== null && isset( $query['bool'] ) ) {
			$query['bool']['boost'] = $this->query_bool_boost;
		}

		// If there are any function score adjustments, then combine those
		if ( $this->functions || $this->decays || $this->scripts || $this->weighting_functions ) {
			$weighting_functions = $this->weighting_functions;

			if ( $this->functions ) {
				foreach ( $this->functions as $function_type => $configs ) {
					foreach ( $configs as $config ) {
						foreach ( $config as $field => $params ) {
							$func_arr = $params;

							$func_arr['field'] = $field;

							$weighting_functions[] = array(
								$function_type => $func_arr,
							);
						}
					}
				}
			}

			if ( $this->decays ) {
				foreach ( $this->decays as $decay_type => $configs ) {
					foreach ( $configs as $config ) {
						foreach ( $config as $field => $params ) {
							$weighting_functions[] = array(
								$decay_type => array(
									$field => $params,
								),
							);
						}
					}
				}
			}

			if ( $this->scripts ) {
				foreach ( $this->scripts as $script ) {
					$weighting_functions[] = array(
						'script_score' => array(
							'script' => $script,
						),
					);
				}
			}

			$query = array(
				'function_score' => array(
					'query'      => $query,
					'functions'  => $weighting_functions,
					'max_boost'  => $this->functions_max_boost,
					'score_mode' => $this->functions_score_mode,
					'boost_mode' => $this->functions_boost_mode,
				),
			);
		}

		return $query;
	}

	/**
	 * Assemble the 'filter' portion of an ES query, from all registered filters
	 *
	 * @return array|null Combined ES filters, or null if none have been defined
	 */
	public function build_filter() {
		if ( empty( $this->es_filters ) ) {
			$filter = null;
		} elseif ( 1 === count( $this->es_filters ) ) {
			$filter = $this->es_filters[0];
		} else {
			$filter = array(
				'and' => $this->es_filters,
			);
		}

		return $filter;
	}

	/**
	 * Assemble the 'aggregation' portion of an ES query, from all general aggregations.
	 *
	 * @return array An aggregation query as an array of topics, filters, and bucket names
	 */
	public function build_aggregation() {
		if ( empty( $this->bucket_sub_aggs ) && empty( $this->aggs_query ) ) {
			return array();
		}

		if ( ! $this->diverse_buckets_query && empty( $this->aggs_query ) ) {
			return $this->bucket_sub_aggs;
		}

		$aggregations = array(
			'topics' => array(
				'filters' => array(
					'filters' => array(),
				),
			),
		);

		if ( ! empty( $this->bucket_sub_aggs ) ) {
			$aggregations['topics']['aggs'] = $this->bucket_sub_aggs;
		}

		foreach ( $this->bucket_filters as $bucket_name => $filter ) {
			$aggregations['topics']['filters']['filters'][ $bucket_name ] = $filter;
		}

		if ( ! empty( $this->aggs_query ) ) {
			$aggregations = $this->aggs;
		}

		return $aggregations;
	}
}
