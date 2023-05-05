import { expect } from '@jest/globals';
import {
	SITE_BACKUP_POLICIES_GET,
	SITE_BACKUP_POLICIES_GET_SUCCESS,
	SITE_BACKUP_POLICIES_GET_FAILED,
} from '../../actions/types';
import siteBackupPolicies from '../site-backup-policies';

describe( 'reducer', () => {
	const fixtures = {
		initialState: {
			isFetching: false,
			loaded: false,
			activityLogLimitDays: null,
			storageLimitBytes: null,
		},
		fetchingState: {
			isFetching: true,
			loaded: false,
			activityLogLimitDays: null,
			storageLimitBytes: null,
		},
		failedState: {
			isFetching: false,
			loaded: true,
			activityLogLimitDays: null,
			storageLimitBytes: null,
		},
	};

	describe( 'siteBackupPolicies()', () => {
		it.each( [
			{
				state: undefined,
				action: {},
				expected: fixtures.initialState,
			},
			{
				state: fixtures.initialState,
				action: { type: SITE_BACKUP_POLICIES_GET },
				expected: fixtures.fetchingState,
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_POLICIES_GET_SUCCESS,
					payload: {
						activityLogLimitDays: 30,
						storageLimitBytes: 10737418240,
					},
				},
				expected: {
					isFetching: false,
					loaded: true,
					activityLogLimitDays: 30,
					storageLimitBytes: 10737418240,
				},
			},
			{
				state: fixtures.initialState,
				action: {
					type: SITE_BACKUP_POLICIES_GET_FAILED,
				},
				expected: fixtures.failedState,
			},
		] )( 'should return expected state', ( { state, action, expected } ) => {
			expect( siteBackupPolicies( state, action ) ).toEqual( expected );
		} );
	} );
} );
