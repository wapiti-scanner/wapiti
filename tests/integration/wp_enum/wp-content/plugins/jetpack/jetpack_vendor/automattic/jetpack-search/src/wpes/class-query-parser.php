<?php
/**
 * Parse a pure text query into WordPress Elasticsearch query. This builds on
 * the Query_Builder() to provide search query parsing.
 *
 * The key part of this parser is taking a user's query string typed into a box
 * and converting it into an ES search query.
 *
 * This varies by application, but roughly it means extracting some parts of the query
 * (authors, tags, and phrases) that are treated as a filter. Then taking the
 * remaining words and building the correct query (possibly with prefix searching
 * if we are doing search as you type)
 *
 * This class only supports ES 2.x+
 *
 * Disables comment chehcks.
 * phpcs:disable Squiz.Commenting
 *
 * This parser builds queries of the form:
 *   bool:
 *     must:
 *       AND match of a single field (ideally an edgengram field)
 *     filter:
 *       filter clauses from context (eg @gibrown, #news, etc)
 *     should:
 *       boosting of results by various fields
 *
 * Features supported:
 *  - search as you type
 *  - phrases
 *  - supports querying across multiple languages at once
 *
 * @package    automattic/jetpack-search
 */

namespace Automattic\Jetpack\Search\WPES;

/**
 * Query parser class.
 */
class Query_Parser extends Query_Builder {
	protected $orig_query    = '';
	protected $current_query = '';
	protected $langs;
	protected $avail_langs = array( 'ar', 'bg', 'ca', 'cs', 'da', 'de', 'el', 'en', 'es', 'eu', 'fa', 'fi', 'fr', 'he', 'hi', 'hu', 'hy', 'id', 'it', 'ja', 'ko', 'nl', 'no', 'pt', 'ro', 'ru', 'sv', 'tr', 'zh' );

	public function __construct( $user_query, $langs ) {
		$this->orig_query    = $user_query;
		$this->current_query = $this->orig_query;
		$this->langs         = $this->norm_langs( $langs );
	}

	protected $extracted_phrases = array();

	public function get_current_query() {
		return $this->current_query;
	}

	public function set_current_query( $q ) {
		$this->current_query = $q;
	}

	///////////////////////////////////////////////////////
	// Methods for Building arrays of multilingual fields

	/*
	 * Normalize language codes
	 */
	public function norm_langs( $langs ) {
		$lst = array();
		foreach ( $langs as $l ) {
			$l = strtok( $l, '-_' );
			if ( in_array( $l, $this->avail_langs, true ) ) {
				$lst[ $l ] = true;
			} else {
				$lst['default'] = true;
			}
		}
		return array_keys( $lst );
	}

	public function get_lang_field_suffix() {
		if ( ! is_array( $this->langs ) || empty( $this->langs ) ) {
			return;
		}

		// Returns the first language only
		return $this->langs[0];
	}

	/*
	 * Take a list of field prefixes and expand them for multi-lingual
	 * with the provided boostings.
	 */
	public function merge_ml_fields( $fields2boosts, $additional_fields ) {
		$flds = array();
		foreach ( $fields2boosts as $f => $b ) {
			foreach ( $this->langs as $l ) {
				$flds[] = $f . '.' . $l . '^' . $b;
			}
		}
		foreach ( $additional_fields as $f ) {
			$flds[] = $f;
		}
		return $flds;
	}

	////////////////////////////////////
	// Extract Fields for Filtering on

	/*
	 * Extract any @mentions from the user query
	 *  use them as a filter if we can find a wp.com id
	 *  otherwise use them as a
	 *
	 *  args:
	 *    wpcom_id_field: wp.com id field
	 *    must_query_fields: array of fields to search for matching results (optional)
	 *    boost_query_fields: array of fields to search in for boosting results (optional)
	 *    prefixes: array of prefixes that the user can use to indicate an author
	 *
	 *  returns true/false of whether any were found
	 *
	 * See also: https://github.com/twitter/twitter-text/blob/master/java/src/com/twitter/Regex.java
	 */
	public function author_field_filter( $args ) {
		$defaults = array(
			'wpcom_id_field'     => 'author_id',
			'must_query_fields'  => null,
			'boost_query_fields' => null,
			'prefixes'           => array( '@' ),
		);
		$args     = wp_parse_args( $args, $defaults );

		$names = array();
		foreach ( $args['prefixes'] as $p ) {
			$found = $this->get_fields( $p );
			if ( $found ) {
				foreach ( $found as $f ) {
					$names[] = $f;
				}
			}
		}

		if ( empty( $names ) ) {
			return false;
		}

		foreach ( $args['prefixes'] as $p ) {
			$this->remove_fields( $p );
		}

		$user_ids = array();

		//loop through the matches and separate into filters and queries
		foreach ( $names as $n ) {
			//check for exact match on login
			$userdata  = get_user_by( 'login', strtolower( $n ) );
			$filtering = false;
			if ( $userdata ) {
				$user_ids[ $userdata->ID ] = true;
				$filtering                 = true;
			}

			$is_phrase = false;
			if ( preg_match( '/"/', $n ) ) {
				$is_phrase = true;
				$n         = preg_replace( '/"/', '', $n );
			}

			if ( ! empty( $args['must_query_fields'] ) && ! $filtering ) {
				if ( $is_phrase ) {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['must_query_fields'],
								'query'  => $n,
								'type'   => 'phrase',
							),
						)
					);
				} else {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['must_query_fields'],
								'query'  => $n,
							),
						)
					);
				}
			}

			if ( ! empty( $args['boost_query_fields'] ) ) {
				if ( $is_phrase ) {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['boost_query_fields'],
								'query'  => $n,
								'type'   => 'phrase',
							),
						),
						'should'
					);
				} else {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['boost_query_fields'],
								'query'  => $n,
							),
						),
						'should'
					);
				}
			}
		}

		if ( ! empty( $user_ids ) ) {
			$user_ids = array_keys( $user_ids );
			$this->add_filter( array( 'terms' => array( $args['wpcom_id_field'] => $user_ids ) ) );
		}

		return true;
	}

	/*
	 * Extract any prefix followed by text use them as a must clause,
	 *   and optionally as a boost to the should query
	 *   This can be used for hashtags. eg #News, or #"current events",
	 *   but also works for any arbitrary field. eg from:Greg
	 *
	 *  args:
	 *    must_query_fields: array of fields that must match the tag (optional)
	 *    boost_query_fields: array of fields to boost search on (optional)
	 *    prefixes: array of prefixes that the user can use to indicate a tag
	 *
	 *  returns true/false of whether any were found
	 *
	 */
	public function text_field_filter( $args ) {
		$defaults = array(
			'must_query_fields'  => array( 'tag.name' ),
			'boost_query_fields' => array( 'tag.name' ),
			'prefixes'           => array( '#' ),
		);
		$args     = wp_parse_args( $args, $defaults );

		$tags = array();
		foreach ( $args['prefixes'] as $p ) {
			$found = $this->get_fields( $p );
			if ( $found ) {
				foreach ( $found as $f ) {
					$tags[] = $f;
				}
			}
		}

		if ( empty( $tags ) ) {
			return false;
		}

		foreach ( $args['prefixes'] as $p ) {
			$this->remove_fields( $p );
		}

		foreach ( $tags as $t ) {
			$is_phrase = false;
			if ( preg_match( '/"/', $t ) ) {
				$is_phrase = true;
				$t         = preg_replace( '/"/', '', $t );
			}

			if ( ! empty( $args['must_query_fields'] ) ) {
				if ( $is_phrase ) {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['must_query_fields'],
								'query'  => $t,
								'type'   => 'phrase',
							),
						)
					);
				} else {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['must_query_fields'],
								'query'  => $t,
							),
						)
					);
				}
			}

			if ( ! empty( $args['boost_query_fields'] ) ) {
				if ( $is_phrase ) {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['boost_query_fields'],
								'query'  => $t,
								'type'   => 'phrase',
							),
						),
						'should'
					);
				} else {
					$this->add_query(
						array(
							'multi_match' => array(
								'fields' => $args['boost_query_fields'],
								'query'  => $t,
							),
						),
						'should'
					);
				}
			}
		}

		return true;
	}

	/*
	 * Extract anything surrounded by quotes or if there is an opening quote
	 *   that is not complete, and add them to the query as a phrase query.
	 *   Quotes can be either '' or ""
	 *
	 *  args:
	 *    must_query_fields: array of fields that must match the phrases
	 *    boost_query_fields: array of fields to boost the phrases on (optional)
	 *
	 *  returns true/false of whether any were found
	 *
	 */
	public function phrase_filter( $args ) {
		$defaults = array(
			'must_query_fields'  => array( 'all_content' ),
			'boost_query_fields' => array( 'title' ),
		);
		$args     = wp_parse_args( $args, $defaults );

		$phrases = array();
		if ( preg_match_all( '/"([^"]+)"/', $this->current_query, $matches ) ) {
			foreach ( $matches[1] as $match ) {
				$phrases[] = $match;
			}
			$this->current_query = preg_replace( '/"([^"]+)"/', '', $this->current_query );
		}

		if ( preg_match_all( "/'([^']+)'/", $this->current_query, $matches ) ) {
			foreach ( $matches[1] as $match ) {
				$phrases[] = $match;
			}
			$this->current_query = preg_replace( "/'([^']+)'/", '', $this->current_query );
		}

		//look for a final, uncompleted phrase
		$phrase_prefix = false;
		if ( preg_match_all( '/"([^"]+)$/', $this->current_query, $matches ) ) {
			$phrase_prefix       = $matches[1][0];
			$this->current_query = preg_replace( '/"([^"]+)$/', '', $this->current_query );
		}
		if ( preg_match_all( "/(?:'\B|\B')([^']+)$/", $this->current_query, $matches ) ) {
			$phrase_prefix       = $matches[1][0];
			$this->current_query = preg_replace( "/(?:'\B|\B')([^']+)$/", '', $this->current_query );
		}

		if ( $phrase_prefix ) {
			$phrases[] = $phrase_prefix;
		}
		if ( empty( $phrases ) ) {
			return false;
		}

		foreach ( $phrases as $p ) {
			$this->add_query(
				array(
					'multi_match' => array(
						'fields' => $args['must_query_fields'],
						'query'  => $p,
						'type'   => 'phrase',
					),
				)
			);

			if ( ! empty( $args['boost_query_fields'] ) ) {
				$this->add_query(
					array(
						'multi_match' => array(
							'fields'   => $args['boost_query_fields'],
							'query'    => $p,
							'operator' => 'and',
						),
					),
					'should'
				);
			}
		}

		return true;
	}

	/*
	 * Query fields based on the remaining parts of the query
	 *   This could be the final AND part of the query terms to match, or it
	 *   could be boosting certain elements of the query
	 *
	 *  args:
	 *    must_query_fields: array of fields that must match the remaining terms (optional)
	 *    boost_query_fields: array of fields to boost the remaining terms on (optional)
	 *
	 */
	public function remaining_query( $args ) {
		$defaults = array(
			'must_query_fields'  => null,
			'boost_query_fields' => null,
			'boost_operator'     => 'and',
			'boost_query_type'   => 'best_fields',
		);
		$args     = wp_parse_args( $args, $defaults );

		if ( empty( $this->current_query ) || ctype_space( $this->current_query ) ) {
			return;
		}

		if ( ! empty( $args['must_query_fields'] ) ) {
			$this->add_query(
				array(
					'multi_match' => array(
						'fields'   => $args['must_query_fields'],
						'query'    => $this->current_query,
						'operator' => 'and',
					),
				)
			);
		}

		if ( ! empty( $args['boost_query_fields'] ) ) {
			$this->add_query(
				array(
					'multi_match' => array(
						'fields'   => $args['boost_query_fields'],
						'query'    => $this->current_query,
						'operator' => $args['boost_operator'],
						'type'     => $args['boost_query_type'],
					),
				),
				'should'
			);
		}
	}

	/*
	 * Query fields using a prefix query (alphabetical expansions on the index).
	 *   This is not recommended. Slower performance and worse relevancy.
	 *
	 *  (UNTESTED! Copied from old prefix expansion code)
	 *
	 *  args:
	 *    must_query_fields: array of fields that must match the remaining terms (optional)
	 *    boost_query_fields: array of fields to boost the remaining terms on (optional)
	 *
	 */
	public function remaining_prefix_query( $args ) {
		$defaults = array(
			'must_query_fields'  => array( 'all_content' ),
			'boost_query_fields' => array( 'title' ),
			'boost_operator'     => 'and',
			'boost_query_type'   => 'best_fields',
		);
		$args     = wp_parse_args( $args, $defaults );

		if ( empty( $this->current_query ) || ctype_space( $this->current_query ) ) {
			return;
		}

		//////////////////////////////////
		// Example cases to think about:
		// "elasticse"
		// "elasticsearch"
		// "elasticsearch "
		// "elasticsearch lucen"
		// "elasticsearch lucene"
		// "the future"  - note the stopword which will match nothing!
		// "F1" - an exact match that also has tons of expansions
		// "こんにちは" ja "hello"
		// "こんにちは友人" ja "hello friend" - we just rely on the prefix phrase and ES to split words
		//   - this could still be better I bet. Maybe we need to analyze with ES first?
		//

		/////////////////////////////
		//extract pieces of query
		// eg: "PREFIXREMAINDER PREFIXWORD"
		//     "elasticsearch lucen"

		$prefix_word      = false;
		$prefix_remainder = false;
		if ( preg_match_all( '/([^ ]+)$/', $this->current_query, $matches ) ) {
			$prefix_word = $matches[1][0];
		}

		$prefix_remainder = preg_replace( '/([^ ]+)$/', '', $this->current_query );
		if ( ctype_space( $prefix_remainder ) ) {
			$prefix_remainder = false;
		}

		if ( ! $prefix_word ) {
			//Space at the end of the query, so skip using a prefix query
			if ( ! empty( $args['must_query_fields'] ) ) {
				$this->add_query(
					array(
						'multi_match' => array(
							'fields'   => $args['must_query_fields'],
							'query'    => $this->current_query,
							'operator' => 'and',
						),
					)
				);
			}

			if ( ! empty( $args['boost_query_fields'] ) ) {
				$this->add_query(
					array(
						'multi_match' => array(
							'fields'   => $args['boost_query_fields'],
							'query'    => $this->current_query,
							'operator' => $args['boost_operator'],
							'type'     => $args['boost_query_type'],
						),
					),
					'should'
				);
			}
		} else {

			//must match the prefix word and the prefix remainder
			if ( ! empty( $args['must_query_fields'] ) ) {
				//need to do an OR across a few fields to handle all cases
				$must_q = array(
					'bool' => array(
						'should'               => array(),
						'minimum_should_match' => 1,
					),
				);

				//treat all words as an exact search (boosts complete word like "news"
				//from prefixes of "newspaper")
				$must_q['bool']['should'][] = array(
					'multi_match' => array(
						'fields'   => $this->all_fields,
						// NOTE: This line has been disabled since $full_text is not available.
						// 'query'    => $full_text,
						'operator' => 'and',
						'type'     => 'cross_fields',
					),
				);

				//always optimistically try and match the full text as a phrase
				//prefix "the futu" should try to match "the future"
				//otherwise the first stopword kinda breaks
				//This also works as the prefix match for a single word "elasticsea"
				$must_q['bool']['should'][] = array(
					'multi_match' => array(
						'fields'         => $this->phrase_fields,
						// NOTE: This line has been disabled since $full_text is not available.
						// 'query'          => $full_text,
						'operator'       => 'and',
						'type'           => 'phrase_prefix',
						'max_expansions' => 100,
					),
				);

				if ( $prefix_remainder ) {
					//Multiple words found, so treat each word on its own and not just as
					//a part of a phrase
					//"elasticsearch lucen" => "elasticsearch" exact AND "lucen" prefix
					$must_q['bool']['should'][] = array(
						'bool' => array(
							'must' => array(
								array(
									'multi_match' => array(
										'fields'         => $this->phrase_fields,
										'query'          => $prefix_word,
										'operator'       => 'and',
										'type'           => 'phrase_prefix',
										'max_expansions' => 100,
									),
								),
								array(
									'multi_match' => array(
										'fields'   => $this->all_fields,
										'query'    => $prefix_remainder,
										'operator' => 'and',
										'type'     => 'cross_fields',
									),
								),
							),
						),
					);
				}

				$this->add_query( $must_q );
			}

			//Now add any boosting of the query
			if ( ! empty( $args['boost_query_fields'] ) ) {
				//treat all words as an exact search (boosts complete word like "news"
				//from prefixes of "newspaper")
				$this->add_query(
					array(
						'multi_match' => array(
							'fields'   => $args['boost_query_fields'],
							'query'    => $this->current_query,
							'operator' => $args['boost_query_operator'],
							'type'     => $args['boost_query_type'],
						),
					),
					'should'
				);

				//optimistically boost the full phrase prefix match
				$this->add_query(
					array(
						'multi_match' => array(
							'fields'         => $args['boost_query_fields'],
							'query'          => $this->current_query,
							'operator'       => 'and',
							'type'           => 'phrase_prefix',
							'max_expansions' => 100,
						),
					)
				);
			}
		}
	}

	/*
	 * Boost results based on the lang probability overlaps
	 *
	 *  args:
	 *    langs2prob: list of languages to search in with associated boosts
	 */
	public function boost_lang_probs( $langs2prob ) {
		foreach ( $langs2prob as $p ) {
			$this->add_function(
				'field_value_factor',
				array(
					'modifier' => 'none',
					'factor'   => $p,
					'missing'  => 0.01, //1% chance doc did not have right lang detected
				)
			);
		}
	}

	////////////////////////////////////
	// Helper Methods

	//Get the text after some prefix. eg @gibrown, or @"Greg Brown"
	protected function get_fields( $field_prefix ) {
		$regex = '/' . $field_prefix . '(("[^"]+")|([^\\p{Z}]+))/';
		if ( preg_match_all( $regex, $this->current_query, $match ) ) {
			return $match[1];
		}
		return false;
	}

	//Remove the prefix and text from the query
	protected function remove_fields( $field_name ) {
		$regex               = '/' . $field_name . '(("[^"]+")|([^\\p{Z}]+))/';
		$this->current_query = preg_replace( $regex, '', $this->current_query );
	}

	//Best effort string truncation that splits on word breaks
	protected function truncate_string( $string, $limit, $break = ' ' ) {
		if ( mb_strwidth( $string ) <= $limit ) {
			return $string;
		}

		// walk backwards from $limit to find first break
		$breakpoint = $limit;
		$broken     = false;
		while ( $breakpoint > 0 ) {
			if ( mb_strimwidth( $string, $breakpoint, 1 ) === $break ) {
				$string = mb_strimwidth( $string, 0, $breakpoint );
				$broken = true;
				break;
			}
			--$breakpoint;
		}
		// if we weren't able to find a break, need to chop mid-word
		if ( ! $broken ) {
			$string = mb_strimwidth( $string, 0, $limit );
		}
		return $string;
	}

}
