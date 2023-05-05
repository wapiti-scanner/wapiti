/* global wpforms_challenge_admin */
/**
 * WPForms Challenge function.
 *
 * @since 1.5.0
 * @since 1.6.2 Challenge v2
 */
'use strict';

var WPFormsChallenge = window.WPFormsChallenge || {};

WPFormsChallenge.core = window.WPFormsChallenge.core || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var app = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.6.2
	 *
	 * @type {object}
	 */
	var vars = {};

	/**
	 * DOM elements.
	 *
	 * @since 1.6.2
	 *
	 * @type {object}
	 */
	var el = {};

	/**
	 * Timer functions and properties.
	 *
	 * @since 1.5.0
	 *
	 * @type {object}
	 */
	var timer = {

		/**
		 * Number of minutes to complete the challenge.
		 *
		 * @since 1.5.0
		 *
		 * @type {number}
		 */
		initialSecondsLeft: WPFormsChallenge.admin.l10n.minutes_left * 60,

		/**
		 * Load timer ID.
		 *
		 * @since 1.5.0
		 *
		 * @returns {string} ID from setInterval().
		 */
		loadId: function() {

			return localStorage.getItem( 'wpformsChallengeTimerId' );
		},

		/**
		 * Save timer ID.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} id setInterval() ID to save.
		 */
		saveId: function( id ) {

			localStorage.setItem( 'wpformsChallengeTimerId', id );
		},

		/**
		 * Run the timer.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 *
		 * @returns {string|void} ID from setInterval().
		 */
		run: function( secondsLeft ) {

			if ( 5 === app.loadStep() ) {
				return;
			}

			var timerId = setInterval( function() {

				app.updateTimerUI( secondsLeft );
				secondsLeft--;
				if ( 0 > secondsLeft ) {
					timer.saveSecondsLeft( 0 );
					clearInterval( timerId );
				}
			}, 1000 );

			timer.saveId( timerId );

			return timerId;
		},

		/**
		 * Pause the timer.
		 *
		 * @since 1.5.0
		 */
		pause: function() {

			var timerId;
			var elSeconds;
			var secondsLeft = timer.getSecondsLeft();

			if ( 0 === secondsLeft || 5 === app.loadStep() ) {
				return;
			}

			timerId = timer.loadId();
			clearInterval( timerId );

			elSeconds = $( '#wpforms-challenge-timer' ).data( 'seconds-left' );

			if ( elSeconds ) {
				timer.saveSecondsLeft( elSeconds );
			}
		},

		/**
		 * Resume the timer.
		 *
		 * @since 1.5.0
		 */
		resume: function() {

			var timerId;
			var secondsLeft = timer.getSecondsLeft();

			if ( 0 === secondsLeft || 5 === app.loadStep() ) {
				return;
			}

			timerId = timer.loadId();

			if ( timerId ) {
				clearInterval( timerId );
			}

			timer.run( secondsLeft );
		},

		/**
		 * Clear all frontend saved timer data.
		 *
		 * @since 1.5.0
		 */
		clear: function() {

			localStorage.removeItem( 'wpformsChallengeSecondsLeft' );
			localStorage.removeItem( 'wpformsChallengeTimerId' );
			localStorage.removeItem( 'wpformsChallengeTimerStatus' );
			$( '#wpforms-challenge-timer' ).removeData( 'seconds-left' );
		},

		/**
		 * Get number of seconds left to complete the Challenge.
		 *
		 * @since 1.5.0
		 *
		 * @returns {number} Number of seconds left to complete the Challenge.
		 */
		getSecondsLeft: function() {

			var secondsLeft = localStorage.getItem( 'wpformsChallengeSecondsLeft' );
			secondsLeft = parseInt( secondsLeft, 10 ) || 0;

			return secondsLeft;
		},

		/**
		 * Get number of seconds spent completing the Challenge.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 *
		 * @returns {number} Number of seconds spent completing the Challenge.
		 */
		getSecondsSpent: function( secondsLeft ) {

			secondsLeft = secondsLeft || timer.getSecondsLeft();

			return timer.initialSecondsLeft - secondsLeft;
		},

		/**
		 * Save number of seconds left to complete the Challenge.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} secondsLeft Number of seconds left to complete the Challenge.
		 */
		saveSecondsLeft: function( secondsLeft ) {

			localStorage.setItem( 'wpformsChallengeSecondsLeft', secondsLeft );
		},

		/**
		 * Get 'minutes' part of timer display.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 *
		 * @returns {number} 'Minutes' part of timer display.
		 */
		getMinutesFormatted: function( secondsLeft ) {

			secondsLeft = secondsLeft || timer.getSecondsLeft();

			return Math.floor( secondsLeft / 60 );
		},

		/**
		 * Get 'seconds' part of timer display.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 *
		 * @returns {number} 'Seconds' part of timer display.
		 */
		getSecondsFormatted: function( secondsLeft ) {

			secondsLeft = secondsLeft || timer.getSecondsLeft();

			return secondsLeft % 60;
		},

		/**
		 * Get formatted timer for display.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 *
		 * @returns {string} Formatted timer for display.
		 */
		getFormatted: function( secondsLeft ) {

			secondsLeft = secondsLeft || timer.getSecondsLeft();

			var timerMinutes = timer.getMinutesFormatted( secondsLeft );
			var timerSeconds = timer.getSecondsFormatted( secondsLeft );

			return timerMinutes + ( 9 < timerSeconds ? ':' : ':0' ) + timerSeconds;
		},
	};

	/**
	 * Public functions and properties.
	 */
	app = {

		/**
		 * Public timer functions and properties.
		 *
		 * @since 1.5.0
		 */
		timer: timer,

		/**
		 * Start the engine.
		 *
		 * @since 1.5.0
		 */
		init: function() {

			$( app.ready );
			$( window ).on( 'load', function() {

				// in case of jQuery 3.+ we need to wait for an `ready` event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.5.0
		 */
		ready: function() {

			app.setup();
			app.events();
		},

		/**
		 * Window load.
		 *
		 * @since 1.5.0
		 */
		load: function() {

			if ( wpforms_challenge_admin.option.status === 'started' ) {
				app.timer.run( app.timer.getSecondsLeft() );
			}
		},

		/**
		 * Initial setup.
		 *
		 * @since 1.5.0
		 */
		setup: function() {

			var secondsLeft;
			var timerId = app.timer.loadId();

			if ( timerId ) {
				clearInterval( timerId );
				secondsLeft = app.timer.getSecondsLeft();
			}

			if ( ! timerId || 0 === app.loadStep() || wpforms_challenge_admin.option.status === 'inited' ) {
				secondsLeft = app.timer.initialSecondsLeft;
			}

			app.initElements();
			app.refreshStep();
			app.initListUI( null, true );
			app.updateListUI();
			app.updateTimerUI( secondsLeft );
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.5.0
		 */
		events: function() {

			$( [ window, document ] )
				.on( 'blur', app.pauseChallenge )
				.on( 'focus', app.resumeChallenge )
				.on( 'click', '.wpforms-challenge-done-btn', app.resumeChallenge );

			el.$btnPause.on( 'click', app.pauseChallenge );
			el.$btnResume.on( 'click', app.resumeChallenge );

			el.$listSteps.on( 'click', '.wpforms-challenge-item-current', app.refreshPage );
		},

		/**
		 * DOM elements.
		 *
		 * @since 1.6.2
		 */
		initElements: function() {

			el = {
				$challenge:     $( '.wpforms-challenge' ),
				$btnPause:      $( '.wpforms-challenge-pause' ),
				$btnResume:     $( '.wpforms-challenge-resume' ),
				$listSteps:     $( '.wpforms-challenge-list' ),
				$listBlock:     $( '.wpforms-challenge-list-block' ),
				$listBtnToggle: $( '.wpforms-challenge-list-block .toggle-list' ),
				$progressBar:   $( '.wpforms-challenge-bar' ),
				$tooltipBtnDone: function() {
					return $( '.wpforms-challenge-tooltip .wpforms-challenge-done-btn' );
				},
			};
		},

		/**
		 * Get last saved step.
		 *
		 * @since 1.5.0
		 *
		 * @returns {number} Last saved step.
		 */
		loadStep: function() {

			var step = localStorage.getItem( 'wpformsChallengeStep' );
			step = parseInt( step, 10 ) || 0;

			return step;
		},

		/**
		 * Save Challenge step.
		 *
		 * @param {number|string} step Step to save.
		 *
		 * @returns {object} jqXHR object from saveChallengeOption().
		 */
		saveStep: function( step ) {

			localStorage.setItem( 'wpformsChallengeStep', step );

			return WPFormsChallenge.admin.saveChallengeOption( { step: step } );
		},

		/**
		 * Update a step with backend data.
		 *
		 * @since 1.5.0
		 */
		refreshStep: function() {

			var savedStep = el.$challenge.data( 'wpforms-challenge-saved-step' );
			savedStep = parseInt( savedStep, 10 ) || 0;

			// Step saved on a backend has a priority.
			if ( app.loadStep() !== savedStep ) {
				app.saveStep( savedStep );
			}
		},

		/**
		 * Complete Challenge step.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} step Step to complete.
		 *
		 * @returns {object} jqXHR object from saveStep().
		 */
		stepCompleted: function( step ) {

			app.updateListUI( step );
			app.updateTooltipUI( step );

			return app.saveStep( step );
		},

		/**
		 * Initialize Challenge tooltips.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} step   Last saved step.
		 * @param {string}        anchor Element selector to bind tooltip to.
		 * @param {object}        args   Tooltipster arguments.
		 */
		initTooltips: function( step, anchor, args ) {

			if ( typeof $.fn.tooltipster === 'undefined' ) {
				return;
			}

			var $dot = $( '<span class="wpforms-challenge-dot wpforms-challenge-dot-step' + step + '" data-wpforms-challenge-step="' + step + '">&nbsp;</span>' );
			var tooltipsterArgs = {
				content          : $( '#tooltip-content' + step ),
				trigger          : null,
				interactive      : true,
				animationDuration: 0,
				delay            : 0,
				theme            : [ 'tooltipster-default', 'wpforms-challenge-tooltip' ],
				side             : [ 'top' ],
				distance         : 3,
				functionReady    : function( instance, helper ) {

					$( helper.tooltip ).addClass( 'wpforms-challenge-tooltip-step' + step );

					// Custom positioning.
					if ( step === 4 || step === 3 ) {
						instance.option( 'side', 'right' );
					} else if ( step === 1 ) {
						instance.option( 'side', 'left' );
					}

					// Reposition is needed to render max-width CSS correctly.
					instance.reposition();
				},
			};

			if ( typeof args === 'object' && args !== null ) {
				$.extend( tooltipsterArgs, args );
			}

			$dot.insertAfter( anchor ).tooltipster( tooltipsterArgs );
		},

		/**
		 * Update tooltips appearance.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} step Last saved step.
		 */
		updateTooltipUI: function( step ) {

			var nextStep;

			step = step || app.loadStep();
			nextStep = step + 1;

			$( '.wpforms-challenge-dot' ).each( function( i, el ) {

				var $dot = $( el ),
					elStep = $dot.data( 'wpforms-challenge-step' );

				if ( elStep < nextStep ) {
					$dot.addClass( 'wpforms-challenge-dot-completed' );
				}

				if ( elStep > nextStep ) {
					$dot.addClass( 'wpforms-challenge-dot-next' );
				}

				if ( elStep === nextStep ) {
					$dot.removeClass( 'wpforms-challenge-dot-completed wpforms-challenge-dot-next' );
				}

				// Zero timeout is needed to properly detect $el visibility.
				setTimeout( function() {
					if ( $dot.is( ':visible' ) && elStep === nextStep ) {
						$dot.tooltipster( 'open' );
					} else {
						$dot.tooltipster( 'close' );
					}
				}, 0 );
			} );
		},

		/**
		 * Init ListUI.
		 *
		 * @since 1.6.2
		 *
		 * @param {number|string} status  Challenge status.
		 * @param {boolean}       initial Initial run, false by default.
		 */
		initListUI: function( status, initial ) {

			status = status || wpforms_challenge_admin.option.status;

			if ( [ 'started', 'paused' ].indexOf( status ) > -1 ) {
				el.$listBlock.find( 'p' ).hide();
				el.$listBtnToggle.show();
				el.$progressBar.show();

				// Transform skip button to cancel button.
				var $skipBtn = el.$listBlock.find( '.list-block-button.challenge-skip' );

				$skipBtn
					.attr( 'title', $skipBtn.data( 'cancel-title' ) )
					.removeClass( 'challenge-skip' )
					.addClass( 'challenge-cancel' );
			}

			// Set initial window closed (collapsed) state if window is short or if it is closed manually.
			if (
				initial &&
				(
					( $( window ).height() < 900 && wpforms_challenge_admin.option.window_closed === '' ) ||
					wpforms_challenge_admin.option.window_closed === '1'
				)
			) {
				el.$listBlock.find( 'p' ).hide();
				el.$listBtnToggle.trigger( 'click' );
			}

			if ( status === 'paused' ) {

				el.$challenge.addClass( 'paused' );
				el.$btnPause.hide();
				el.$btnResume.show();

			} else {

				// Zero timeout is needed to avoid firing 'focus' and 'click' events in the same loop.
				setTimeout( function() {
					el.$btnPause.show();
				}, 0 );

				el.$challenge.removeClass( 'paused' );
				el.$btnResume.hide();

			}
		},

		/**
		 * Update Challenge task list appearance.
		 *
		 * @since 1.5.0
		 *
		 * @param {number|string} step Last saved step.
		 */
		updateListUI: function( step ) {

			step = step || app.loadStep();

			el.$listSteps.find( 'li' ).slice( 0, step ).addClass( 'wpforms-challenge-item-completed' ).removeClass( 'wpforms-challenge-item-current' );
			el.$listSteps.find( 'li' ).eq( step ).addClass( 'wpforms-challenge-item-current' );
			el.$progressBar.find( 'div' ).css( 'width', ( step * 20 ) + '%' );
		},

		/**
		 * Update Challenge timer appearance.
		 *
		 * @since 1.5.0
		 *
		 * @param {number} secondsLeft Number of seconds left to complete the Challenge.
		 */
		updateTimerUI: function( secondsLeft ) {

			if ( ! secondsLeft || isNaN( secondsLeft ) || '0' === secondsLeft ) {
				secondsLeft = 0;
			}

			app.timer.saveSecondsLeft( secondsLeft );
			$( '#wpforms-challenge-timer' ).text( app.timer.getFormatted( secondsLeft ) ).data( 'seconds-left', secondsLeft );
		},

		/**
		 * Remove Challenge interface.
		 *
		 * @since 1.5.0
		 */
		removeChallengeUI: function() {

			$( '.wpforms-challenge-dot' ).remove();
			el.$challenge.remove();
		},

		/**
		 * Clear all Challenge frontend saved data.
		 *
		 * @since 1.5.0
		 */
		clearLocalStorage: function() {

			localStorage.removeItem( 'wpformsChallengeStep' );
			app.timer.clear();
		},

		/**
		 * Pause Challenge.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} e Event object.
		 */
		pauseChallenge: function( e ) {

			// Skip if out to the iframe.
			if ( document.activeElement.tagName === 'IFRAME' ) {
				return;
			}

			// Skip if is not started.
			if ( wpforms_challenge_admin.option.status !== 'started' ) {
				return;
			}

			vars.pauseEvent = e.type;

			app.pauseResumeChallenge( 'pause' );
		},

		/**
		 * Resume Challenge.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} e Event object.
		 *
		 * @returns {Function|void} Return pause challenge function or void.
		 */
		resumeChallenge: function( e ) {

			// Skip if is not paused.
			if ( wpforms_challenge_admin.option.status !== 'paused' ) {
				return;
			}

			// Resume on 'focus' only if it has been paused on 'blur'.
			if ( e.type === 'focus' && vars.pauseEvent !== 'blur' ) {
				delete vars.pauseEvent;
				return;
			}

			vars.resumeEvent = e.type;

			return app.pauseResumeChallenge( 'resume' );
		},

		/**
		 * Pause/Resume Challenge.
		 *
		 * @since 1.6.2
		 *
		 * @param {string} action Action to perform. `pause` or `resume`.
		 *
		 * @returns {Function} Save challenge option.
		 */
		pauseResumeChallenge: function( action ) {

			action = action === 'pause' ? action : 'resume';

			app.timer[ action ]();

			var optionData = {
				status       : action === 'pause' ? 'paused' : 'started',
				seconds_spent: app.timer.getSecondsSpent(),
				seconds_left : app.timer.getSecondsLeft(),
			};

			app.initListUI( optionData.status );

			return WPFormsChallenge.admin.saveChallengeOption( optionData );
		},

		/**
		 * Resume Challenge and execute the callback.
		 *
		 * @since 1.7.5
		 *
		 * @param {object}   e        Event object.
		 * @param {Function} callback Callback function.
		 */
		resumeChallengeAndExec: function( e, callback ) {

			if ( typeof callback !== 'function' ) {
				callback = function() {};
			}

			if ( wpforms_challenge_admin.option.status !== 'paused' ) {
				callback();

				return;
			}

			var resumeResult = app.resumeChallenge( e );

			if ( typeof resumeResult === 'object' && typeof resumeResult.done === 'function' ) {
				resumeResult.done( callback );
			} else {
				callback();
			}
		},

		/**
		 * Refresh Page in order to re-init current step.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} e Event object.
		 */
		refreshPage: function( e ) {

			window.location.reload( true );
		},

		/**
		 * Check if we're in Gutenberg editor.
		 *
		 * @since 1.5.0
		 *
		 * @returns {boolean} Is Gutenberg or not.
		 */
		isGutenberg: function() {

			return typeof wp !== 'undefined' && Object.prototype.hasOwnProperty.call( wp, 'blocks' );
		},

		/**
		 * Trigger form embed page save potentially reloading it.
		 *
		 * @since 1.5.0
		 */
		triggerPageSave: function() {

			if ( app.isGutenberg() ) {
				app.gutenbergPageSave();

			} else {
				$( '#post #publish' ).trigger( 'click' );
			}
		},

		/**
		 * Save page for Gutenberg.
		 *
		 * @since 1.5.2
		 */
		gutenbergPageSave: function() {

			var $gb = $( '.block-editor' ),
				$updateBtn = $gb.find( '.editor-post-publish-button.editor-post-publish-button__button' );

			// Trigger click on the Update button.
			if ( $updateBtn.length > 0 ) {
				$updateBtn.trigger( 'click' );

				return;
			}

			// Use MutationObserver to wait while Gutenberg create/display panel with Publish button.
			var obs = {
				targetNode  : $gb.find( '.edit-post-layout, .block-editor-editor-skeleton__publish > div' )[0],
				config      : {
					childList: true,
					attributes: true,
					subtree: true,
				},
			};

			obs.callback = function( mutationsList, observer ) {

				var $btn = $gb.find( '.editor-post-publish-button, .editor-post-publish-panel__header-publish-button .editor-post-publish-button__button' );

				if ( $btn.length > 0 ) {
					$btn.trigger( 'click' );
					observer.disconnect();
				}
			};

			obs.observer = new MutationObserver( obs.callback );
			obs.observer.observe( obs.targetNode, obs.config );

			// Trigger click on the Publish button that opens the additional publishing panel.
			$gb.find( '.edit-post-toggle-publish-panel__button, .editor-post-publish-panel__toggle.editor-post-publish-button__button' )
				.trigger( 'click' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

WPFormsChallenge.core.init();
