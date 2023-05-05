const path = require( 'path' );
const jetpackWebpackConfig = require( '@automattic/jetpack-webpack-config/webpack' );
const CopyWebpackPlugin = require( 'copy-webpack-plugin' );

module.exports = [
	{
		entry: {
			'lazy-images': './src/js/lazy-images.js',
			'intersection-observer': require.resolve( 'intersection-observer/intersection-observer.js' ),
		},
		mode: jetpackWebpackConfig.mode,
		devtool: jetpackWebpackConfig.devtool,
		output: {
			...jetpackWebpackConfig.output,
			path: path.resolve( './dist' ),
		},
		optimization: {
			...jetpackWebpackConfig.optimization,
		},
		resolve: {
			...jetpackWebpackConfig.resolve,
		},
		node: false,
		plugins: [
			...jetpackWebpackConfig.StandardPlugins(),
			new CopyWebpackPlugin( {
				patterns: [
					{
						from: require.resolve( 'intersection-observer/intersection-observer.js' ),
						to: 'intersection-observer.src.js',
					},
				],
			} ),
		],
		module: {
			strictExportPresence: true,
			rules: [
				// Transpile JavaScript, including node_modules.
				jetpackWebpackConfig.TranspileRule(),
			],
		},
	},
];
