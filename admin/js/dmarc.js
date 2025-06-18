/* global eauthDmarcApi */

jQuery(($) => {
	const orgDomainCache = {};
	class OrgDomainError extends Error {}

	async function getOrgDomain(domain) {
		if (!orgDomainCache[domain]) {
			const response = await EmailAuthPlugin.request(
				`${eauthDmarcApi.org}/${domain}`
			);
			const data = await response.json();

			if (data.fail) {
				throw new OrgDomainError(data.fail);
			}

			orgDomainCache[domain] = data.org || domain;
		}

		return orgDomainCache[domain];
	}

	function makeStatusSetter(hasWarnings, setStatusInfo) {
		return (alignmentStatus, alignmentText, conjunction) => {
			conjunction = conjunction ?? (hasWarnings ? 'and' : 'with');

			let statusCode;
			if (alignmentStatus === 'error') {
				statusCode = 'error';
			} else if (hasWarnings) {
				statusCode = 'partial';
			} else {
				statusCode = alignmentStatus;
			}

			setStatusInfo(
				statusCode,
				`Configured${hasWarnings ? ' with warnings' : ''} ${conjunction} ${alignmentText}.`
			);
		};
	}

	async function runAlignmentCheck(
		name,
		result,
		validateDomain,
		fromDomain,
		relaxed
	) {
		if (result === false) {
			return { level: 'error', desc: `${name} check failed.` };
		}

		if (validateDomain === null) {
			return { level: 'unknown', desc: `${name} alignment unknown.` };
		}

		try {
			if (relaxed && validateDomain !== fromDomain) {
				validateDomain = await getOrgDomain(validateDomain);
				fromDomain = await getOrgDomain(fromDomain);
			}
		} catch (error) {
			if (error instanceof OrgDomainError) {
				return { level: 'unknown', desc: error.message };
			}

			throw error;
		}

		if (validateDomain !== fromDomain) {
			return {
				level: 'error',
				desc: `${name} alignment failed: ${validateDomain} does not match from domain ${fromDomain}.`,
			};
		}

		if (result === null) {
			return { level: 'unknown', desc: `${name} result unknown.` };
		}

		return { level: 'pass', desc: `${name} alignment passed.` };
	}

	function addAlignmentCheck(
		onRun,
		checkId,
		name,
		getDomain,
		domainEvent,
		relaxed
	) {
		const resultEvent = `${checkId}resultchange`;
		const plugin = EmailAuthPlugin.instance;
		const runCheck = async () =>
			onRun(
				await runAlignmentCheck(
					name,
					plugin.results[checkId],
					getDomain(),
					plugin.fromDomain,
					relaxed
				)
			);

		runCheck();
		plugin.addEventListener(resultEvent, runCheck);
		plugin.addEventListener(domainEvent, runCheck);
		plugin.addEventListener('fromdomainchange', runCheck);

		return () => {
			plugin.removeEventListener(resultEvent, runCheck);
			plugin.removeEventListener(domainEvent, runCheck);
			plugin.removeEventListener('fromdomainchange', runCheck);
		};
	}

	function addAlignmentChecks(relaxed, setAlignmentStatus) {
		const results = {
			spf: { level: 'unknown', desc: `Check in progress...` },
			dkim: { level: 'unknown', desc: `Check in progress...` },
		};

		const onRun = (checkId, result) => {
			results[checkId] = result;

			$('.eauth-dmarc-alignment-check-component')
				.first()
				.replaceWith(
					EmailAuthPlugin.createCommentList(
						Object.values(results),
						'Alignment Checks'
					).addClass('eauth-dmarc-alignment-check-component')
				)
				.end()
				.remove();

			const pass = Object.values(results).some(
				({ level }) => level === 'pass'
			);
			if (pass) {
				setAlignmentStatus('pass', 'alignment');
				return;
			}

			const unknown = Object.values(results).some(
				({ level }) => level === 'unknown'
			);
			if (unknown) {
				setAlignmentStatus('unknown', 'unknown alignment');
				return;
			}

			setAlignmentStatus('error', 'alignment checks failed', 'but');
		};

		const d1 = addAlignmentCheck(
			onRun.bind(null, 'spf'),
			'spf',
			'SPF',
			() => EmailAuthPlugin.instance.bounceDomain,
			'bouncedomainchange',
			relaxed.spf
		);

		const d2 = addAlignmentCheck(
			onRun.bind(null, 'dkim'),
			'dkim',
			'DKIM',
			() => EmailAuthPlugin.instance.extra.dkimDomain,
			'dkimdomainchange',
			relaxed.dkim
		);

		return () => {
			d1();
			d2();
		};
	}

	const checker = EmailAuthPlugin.instance.makeChecker(
		'dmarc',
		'DMARC',
		() => `${eauthDmarcApi.check}/${EmailAuthPlugin.instance.fromDomain}`,
		null,
		(res) => {
			return [
				res.orgFail &&
					$('<div>')
						.addClass('notice inline multiline')
						.text(res.orgFail),
				$('<div>').attr(
					'class',
					'eauth-dmarc-alignment-check-component'
				),
				EmailAuthPlugin.createCommentList(
					res.warnings.map((desc) => ({
						level: 'warning',
						desc,
					})),
					'Warnings'
				),
				EmailAuthPlugin.createCommentList(
					res.infos.map((desc) => ({ desc })),
					'Comments'
				),
			];
		},
		{
			get: () => `_dmarc.${EmailAuthPlugin.instance.fromDomain}`,
			getFallback: (res) => res.org && `_dmarc.${res.org}`,
			type: 'From Address',
			link: '#from-address',
		},
		(res, setStatusInfo) => {
			if (!res.pass) {
				setStatusInfo('error', res.reason);
				return;
			}

			const setAlignmentStatus = makeStatusSetter(
				res.pass === 'partial',
				setStatusInfo
			);
			setAlignmentStatus('unknown alignments', 'unknown');

			return addAlignmentChecks(res.relaxed, setAlignmentStatus);
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'fromdomainchange',
		checker.boundCheck
	);
});
