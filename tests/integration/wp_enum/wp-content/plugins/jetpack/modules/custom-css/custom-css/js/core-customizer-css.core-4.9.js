(function( $, customize ){
	/**
	 * Helper function to qet a control by ID
	 * @param  {string} controlId Control ID
	 * @return {object}           jQuery object of the container
	 */
	function _getControl ( controlId ) {
		var control = customize.control.value( controlId );
		if ( control ) {
			return control.container;
		}
		return null;
	}

	/**
	 * Add some labels that the default checkbox controls don't allow.
	 * Add CSS Revisions and CSS Help links.
	 */
	$(document).ready( function(){
		var cssModeControl = _getControl( 'jetpack_css_mode_control' );
		if ( cssModeControl ) {
			cssModeControl.prepend( '<span class="customize-control-title">' + window._jp_css_settings.l10n.mode + '</span>' );
		}

		var mobileCssControl = _getControl( 'jetpack_mobile_css_control' );
		if ( mobileCssControl ) {
			mobileCssControl.prepend( '<span class="customize-control-title">' + window._jp_css_settings.l10n.mobile + '</span>' );
		}

		var widthControl = _getControl( 'wpcom_custom_css_content_width_control' );
		if ( widthControl ) {
			widthControl.append( '<span class="description">' + window._jp_css_settings.l10n.contentWidth + '<span>' );
			widthControl.find( 'input' ).after( '<span>px</span>' );
		}

		$( '<div />', {
			id      : 'css-help-links',
			'class' : 'css-help'
		}).appendTo( _getControl( 'custom_css' ) );

		$( '<a />', {
			id     : 'help-link',
			target : '_blank',
			rel: 'noopener noreferrer',
			href   : window._jp_css_settings.cssHelpUrl,
			text   : window._jp_css_settings.l10n.css_help_title
		}).prependTo( '#css-help-links' );

		// Only show the revisions link if there are revisions
		if ( window._jp_css_settings.areThereCssRevisions ) {
			$( '<a />', {
				id     : 'revisions-link',
				target : '_blank',
				rel: 'noopener noreferrer',
				href   : window._jp_css_settings.revisionsUrl,
				text   : window._jp_css_settings.l10n.revisions
			}).prependTo( '#css-help-links' );
		}

		customize( 'jetpack_custom_css[preprocessor]', function( preprocessorSetting ) {
			preprocessorSetting.bind( function( curr ) {
				var preprocessor_modes = {
						'default' : 'text/css',
						less      : 'text/x-less',
						sass      : 'text/x-scss'
					},
					new_mode = 'text/css';

				if ( 'undefined' !== typeof preprocessor_modes[ curr ] ) {
					new_mode = preprocessor_modes[ curr ];
				}

				customize.control( 'custom_css' ).deferred.codemirror.done( function ( cm ) {
					cm.setOption( 'mode', new_mode );
					if ( 'text/css' === new_mode ) {
						cm.setOption( 'lint', true );
					} else {
						cm.setOption( 'lint', false );
					}
				});
			});
		});
	});

})( jQuery, window.wp.customize );
