import apiFetch from '@wordpress/api-fetch';
import actions from '../index';
import {
	SITE_BACKUP_SIZE_GET,
	SITE_BACKUP_SIZE_GET_FAILED,
	SITE_BACKUP_SIZE_GET_SUCCESS,
} from '../types';

const anyFunction = () => {};
jest.mock( '@wordpress/api-fetch' );

const apiFixtures = {
	requestOptions: {
		path: '/jetpack/v4/site/backup/size',
	},
	successResponse: {
		ok: true,
		error: '',
		size: 7516192768,
	},
	failureResponse: {
		ok: false,
		error: 'Unexpected error',
		size: null,
	},
};

const successPayload = {
	size: apiFixtures.successResponse.size,
};

describe( 'getSiteSize', () => {
	beforeEach( () => jest.clearAllMocks() );

	it( 'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_SIZE_GET_SUCCESS when fetches successfully', async () => {
		const dispatch = jest.fn( anyFunction );
		apiFetch.mockReturnValue( Promise.resolve( apiFixtures.successResponse ) );

		await actions.getSiteSize()( { dispatch } );
		expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

		expect( dispatch ).toHaveBeenCalledTimes( 2 );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET,
		} );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET_SUCCESS,
			payload: successPayload,
		} );
	} );

	it( 'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_SIZE_GET_FAILED when API call fails', async () => {
		const dispatch = jest.fn( anyFunction );
		apiFetch.mockReturnValue( Promise.reject( 'Timeout error' ) );

		await actions.getSiteSize()( { dispatch } );
		expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

		expect( dispatch ).toHaveBeenCalledTimes( 2 );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET,
		} );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET_FAILED,
		} );
	} );

	it( 'dispatches SITE_BACKUP_SIZE_GET and SITE_BACKUP_SIZE_GET_FAILED when API returns an error', async () => {
		const dispatch = jest.fn( anyFunction );
		apiFetch.mockReturnValue( Promise.resolve( apiFixtures.failureResponse ) );

		await actions.getSiteSize()( { dispatch } );
		expect( apiFetch ).toHaveBeenCalledWith( apiFixtures.requestOptions );

		expect( dispatch ).toHaveBeenCalledTimes( 2 );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET,
		} );
		expect( dispatch ).toHaveBeenCalledWith( {
			type: SITE_BACKUP_SIZE_GET_FAILED,
		} );
	} );
} );
