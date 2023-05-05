// Originally based on https://raw.githubusercontent.com/xwp/wp-custom-scss-demo/master/custom-scss-demo-preview.js
/* globals jpCustomizerCssPreview */
(function( api, $ ) {
	if ( api.settingPreviewHandlers ) {
		// No-op the custom_css preview handler since now handled by partial.
		api.settingPreviewHandlers.custom_css = function() {};
	} else {
		parent.console.warn( 'Missing core patch that adds support for settingPreviewHandlers' );
	}

	api.selectiveRefresh.partialConstructor.custom_css = api.selectiveRefresh.Partial.extend( {

		/**
		 * Refresh custom_css partial, using selective refresh if pre-processor and direct DOM manipulation if otherwise.
		 *
		 * @returns {jQuery.promise}
		 */
		refresh: function() {
			var partial = this,
				preprocessor = api( 'jetpack_custom_css[preprocessor]' ).get(),
				deferred, setting;

			// Sass or Less require Partial -- so ajax call to get it from PHP.
			// We can explicitly override for specific providers by testing if `'sass' === preprocessor`
			if ( jpCustomizerCssPreview.preprocessors.hasOwnProperty( preprocessor ) ) {
				return api.selectiveRefresh.Partial.prototype.refresh.call( partial );
			}

			// No special providers, just write what we got.
			deferred = new $.Deferred();
			setting = api( 'custom_css[' + api.settings.theme.stylesheet + ']' );
			_.each( partial.placements(), function( placement ) {
				placement.container.text( setting.get() );
			} );

			deferred.resolve();
			return deferred.promise();
		}

	} );

}( wp.customize, jQuery ));
