module.exports = api => {
	api.cache( true );
	return {
		presets: [
			[
				'@automattic/jetpack-webpack-config/babel/preset',
				{
					presetEnv: {
						corejs: require( 'core-js/package.json' ).version,
						modules: false,
						useBuiltIns: 'usage',
					},
					pluginReplaceTextdomain: { textdomain: 'jetpack-wordads' },
				},
			],
		],
		plugins: [ '@babel/plugin-proposal-nullish-coalescing-operator' ],
	};
};
