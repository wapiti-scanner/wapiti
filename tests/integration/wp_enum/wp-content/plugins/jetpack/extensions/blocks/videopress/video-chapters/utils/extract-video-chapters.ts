export type VideoPressChapter = {
	startAt: string;
	title: string;
};

/**
 * Extracts chapter information from a single text line
 *
 * @param {string} line         - The line to be processed
 * @returns {VideoPressChapter} - Title and start time of the chapter
 */
function extractSingleChapter( line: string ): VideoPressChapter | null {
	const regex = /(?<timeBlock>\(?(?<time>\d{1,2}:\d{2}:\d{2}|\d{1,2}:\d{2})\)?)/;
	const result = regex.exec( line );

	if ( result == null || result.groups == null ) {
		return null;
	}

	const {
		groups: { timeBlock, time },
	} = result;
	const blockIndex = line.indexOf( timeBlock );
	const remainingLength = line.length - timeBlock.length;

	const title = (
		blockIndex < remainingLength / 2
			? line.substring( blockIndex + timeBlock.length, line.length )
			: line.substring( 0, blockIndex )
	)
		.trim()
		.replace( /(\s-$)|(^-\s)/, '' );

	const timeSections = time.split( ':' );
	if ( timeSections[ 0 ].length === 1 ) {
		timeSections[ 0 ] = `0${ timeSections[ 0 ] }`;
	}
	if ( timeSections.length === 2 ) {
		timeSections.unshift( '00' );
	}

	const startAt = timeSections.join( ':' );

	return { startAt, title };
}

/**
 * Extracts chapter information from a single text line
 *
 * @param {string} text                - The text to be processed
 * @returns {Array<VideoPressChapter>} - Title and start time of all chapters, sorted by start time
 */
export default function extractVideoChapters( text: string ): Array< VideoPressChapter > {
	const lines = text.split( '\n' );

	const chapters = lines
		.map( line => extractSingleChapter( line ) )
		.filter( chapter => chapter !== null ) as Array< VideoPressChapter >;

	return chapters.sort( ( lineA, lineB ) => {
		return lineA.startAt.localeCompare( lineB.startAt );
	} );
}

export { extractSingleChapter, extractVideoChapters };
