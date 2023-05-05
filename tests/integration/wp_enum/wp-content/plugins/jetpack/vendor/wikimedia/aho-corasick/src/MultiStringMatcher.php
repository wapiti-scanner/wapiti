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
 * Represents a finite state machine that can find all occurrences
 * of a set of search keywords in a body of text.
 *
 * The time it takes to construct the finite state machine is
 * proportional to the sum of the lengths of the search keywords.
 * Once constructed, the machine can locate all occurences of all
 * search keywords in a body of text in a single pass, making exactly
 * one state transition per input character.
 *
 * This is an implementation of the Aho-Corasick string matching
 * algorithm.
 *
 * Alfred V. Aho and Margaret J. Corasick, "Efficient string matching:
 *  an aid to bibliographic search", CACM, 18(6):333-340, June 1975.
 *
 * @link http://xlinux.nist.gov/dads//HTML/ahoCorasick.html
 */
class MultiStringMatcher {

	/** @var string[] The set of keywords to be searched for. **/
	protected $searchKeywords = [];

	/** @var int The number of possible states of the string-matching finite state machine. **/
	protected $numStates = 1;

	/** @var array Mapping of states to outputs. **/
	protected $outputs = [];

	/** @var array Mapping of failure transitions. **/
	protected $noTransitions = [];

	/** @var array Mapping of success transitions. **/
	protected $yesTransitions = [];

	/**
	 * Constructor.
	 *
	 * @param string[] $searchKeywords The set of keywords to be matched.
	 */
	public function __construct( array $searchKeywords ) {
		foreach ( $searchKeywords as $keyword ) {
			if ( $keyword !== '' ) {
				$this->searchKeywords[$keyword] = strlen( $keyword );
			}
		}

		if ( !$this->searchKeywords ) {
			trigger_error( __METHOD__ . ': The set of search keywords is empty.', E_USER_WARNING );
			// Unreachable 'return' when PHPUnit detects trigger_error
			return; // @codeCoverageIgnore
		}

		$this->computeYesTransitions();
		$this->computeNoTransitions();
	}

	/**
	 * Accessor for the search keywords.
	 *
	 * @return string[] Search keywords.
	 */
	public function getKeywords() {
		return array_keys( $this->searchKeywords );
	}

	/**
	 * Map the current state and input character to the next state.
	 *
	 * @param int $currentState The current state of the string-matching
	 *  automaton.
	 * @param string $inputChar The character the string-matching
	 *  automaton is currently processing.
	 * @return int The state the automaton should transition to.
	 */
	public function nextState( $currentState, $inputChar ) {
		$initialState = $currentState;
		while ( true ) {
			$transitions =& $this->yesTransitions[$currentState];
			if ( isset( $transitions[$inputChar] ) ) {
				$nextState = $transitions[$inputChar];
				// Avoid failure transitions next time.
				if ( $currentState !== $initialState ) {
					$this->yesTransitions[$initialState][$inputChar] = $nextState;
				}
				return $nextState;
			}
			if ( $currentState === 0 ) {
				return 0;
			}
			$currentState = $this->noTransitions[$currentState];
		}
		// Unreachable outside 'while'
	} // @codeCoverageIgnore

	/**
	 * Locate the search keywords in some text.
	 *
	 * @param string $text The string to search in.
	 * @return array[] An array of matches. Each match is a vector
	 *  containing an integer offset and the matched keyword.
	 *
	 * @par Example:
	 * @code
	 *   $keywords = new MultiStringMatcher( array( 'ore', 'hell' ) );
	 *   $keywords->searchIn( 'She sells sea shells by the sea shore.' );
	 *   // result: array( array( 15, 'hell' ), array( 34, 'ore' ) )
	 * @endcode
	 */
	public function searchIn( $text ) {
		if ( !$this->searchKeywords || $text === '' ) {
			return [];  // fast path
		}

		$state = 0;
		$results = [];
		$length = strlen( $text );

		for ( $i = 0; $i < $length; $i++ ) {
			$ch = $text[$i];
			$state = $this->nextState( $state, $ch );
			foreach ( $this->outputs[$state] as $match ) {
				$offset = $i - $this->searchKeywords[$match] + 1;
				$results[] = [ $offset, $match ];
			}
		}

		return $results;
	}

	/**
	 * Get the state transitions which the string-matching automaton
	 * shall make as it advances through input text.
	 *
	 * Constructs a directed tree with a root node which represents the
	 * initial state of the string-matching automaton and from which a
	 * path exists which spells out each search keyword.
	 */
	protected function computeYesTransitions() {
		$this->yesTransitions = [ [] ];
		$this->outputs = [ [] ];
		foreach ( $this->searchKeywords as $keyword => $length ) {
			$state = 0;
			for ( $i = 0; $i < $length; $i++ ) {
				$ch = $keyword[$i];
				if ( !empty( $this->yesTransitions[$state][$ch] ) ) {
					$state = $this->yesTransitions[$state][$ch];
				} else {
					$this->yesTransitions[$state][$ch] = $this->numStates;
					$this->yesTransitions[] = [];
					$this->outputs[] = [];
					$state = $this->numStates++;
				}
			}

			$this->outputs[$state][] = $keyword;
		}
	}

	/**
	 * Get the state transitions which the string-matching automaton
	 * shall make when a partial match proves false.
	 */
	protected function computeNoTransitions() {
		$queue = [];
		$this->noTransitions = [];

		foreach ( $this->yesTransitions[0] as $ch => $toState ) {
			$queue[] = $toState;
			$this->noTransitions[$toState] = 0;
		}

		while ( true ) {
			$fromState = array_shift( $queue );
			if ( $fromState === null ) {
				break;
			}
			foreach ( $this->yesTransitions[$fromState] as $ch => $toState ) {
				$queue[] = $toState;
				$state = $this->noTransitions[$fromState];

				while ( $state !== 0 && empty( $this->yesTransitions[$state][$ch] ) ) {
					$state = $this->noTransitions[$state];
				}

				if ( isset( $this->yesTransitions[$state][$ch] ) ) {
					$noState = $this->yesTransitions[$state][$ch];
				} else {
					$noState = 0;
				}

				$this->noTransitions[$toState] = $noState;
				$this->outputs[$toState] = array_merge(
					$this->outputs[$toState], $this->outputs[$noState] );
			}
		}
	}
}
