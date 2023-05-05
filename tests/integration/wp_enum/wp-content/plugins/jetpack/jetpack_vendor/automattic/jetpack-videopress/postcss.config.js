module.exports = () => ( {
	plugins: {
		'postcss-custom-properties': {
			importFrom: [ require.resolve( '@automattic/calypso-color-schemes' ) ],
			// Use of `preserve: false` dates back to when we still used @automattic/calypso-build.
			// Ideally we'd get rid of it to properly make use of CSS vars, but first we have to
			// figure out how to ensure the vars actually get defined in the browser without
			// including them in every bundle. Some base stylesheet (wp_register_style) the other
			// stylesheets depend on maybe?
			//
			// See also https://github.com/Automattic/jetpack/pull/13854#issuecomment-550898168,
			// where people were confused about what was going on when calypso-build stopped
			// including a postcss.config.js like this by default.
			preserve: false,
			disableDeprecationNotice: true,
		},
		autoprefixer: {},
	},
} );
