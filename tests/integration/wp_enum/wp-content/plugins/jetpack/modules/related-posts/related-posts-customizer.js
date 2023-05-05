/**
 * Adds functionality for Related Posts controls in Customizer.
 */
( function ( api ) {
	'use strict';

	api( 'jetpack_relatedposts[show_headline]', function ( showHeadlineSetting ) {
		var setupHeadlineControl = function ( headlineControl ) {
			var setActiveState, isDisplayed;

			isDisplayed = function () {
				return showHeadlineSetting.findControls()[ 0 ].active.get() && showHeadlineSetting.get();
			};

			setActiveState = function () {
				headlineControl.active.set( isDisplayed() );
			};

			headlineControl.active.validate = isDisplayed;

			setActiveState();

			showHeadlineSetting.bind( setActiveState );
		};

		api.control( 'jetpack_relatedposts[headline]', setupHeadlineControl );
	} );
} )( wp.customize );
