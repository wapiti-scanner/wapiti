<?php
/**
 * AhoCorasick PHP Library
 *
 * A PHP implementation of the Aho-Corasick string matching algorithm.
 *
 * Alfred V. Aho and Margaret J. Corasick, "Efficient string matching:
 *  an aid to bibliographic search", CACM, 18(6):333-340, June 1975.
 *
 * @link http://xlinux.nist.gov/dads//HTML/ahoCorasick.html
 * @link https://en.wikipedia.org/wiki/Aho-Corasick_string_matching_algorithm
 *
 * Copyright (C) 2015 Ori Livneh <ori@wikimedia.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @file
 * @author Ori Livneh <ori@wikimedia.org>
 */

namespace AhoCorasick;

/**
 * This class extends MultiStringMatcher, adding search and replace
 * functionality.
 */
class MultiStringReplacer extends MultiStringMatcher {

	/** @var array Mapping of states to outputs. **/
	protected $replacePairs = [];

	/**
	 * Constructor.
	 *
	 * @param array $replacePairs array of ( 'from' => 'to' ) replacement pairs.
	 */
	public function __construct( array $replacePairs ) {
		foreach ( $replacePairs as $keyword => $replacement ) {
			if ( $keyword !== '' ) {
				$this->replacePairs[$keyword] = $replacement;
			}
		}
		parent::__construct( array_keys( $this->replacePairs ) );
	}

	/**
	 * Search and replace a set of keywords in some text.
	 *
	 * @param string $text The string to search in.
	 * @return string The input text with replacements.
	 *
	 * @par Example:
	 * @code
	 *   $replacer = new MultiStringReplacer( array( 'csh' => 'sea shells' ) );
	 *   $replacer->searchAndReplace( 'She sells csh by the sea shore.' );
	 *   // result: 'She sells sea shells by the sea shore.'
	 * @endcode
	 */
	public function searchAndReplace( $text ) {
		$state = 0;
		$length = strlen( $text );
		$matches = [];
		for ( $i = 0; $i < $length; $i++ ) {
			$ch = $text[$i];
			$state = $this->nextState( $state, $ch );
			foreach ( $this->outputs[$state] as $match ) {
				$offset = $i - $this->searchKeywords[$match] + 1;
				$matches[$offset] = $match;
			}
		}
		ksort( $matches );

		$buf = '';
		$lastInsert = 0;
		foreach ( $matches as $offset => $match ) {
			if ( $offset >= $lastInsert ) {
				$buf .= substr( $text, $lastInsert, $offset - $lastInsert );
				$buf .= $this->replacePairs[$match];
				$lastInsert = $offset + $this->searchKeywords[$match];
			}
		}
		$buf .= substr( $text, $lastInsert );

		return $buf;
	}
}
