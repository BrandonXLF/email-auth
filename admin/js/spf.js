/* global eauthSpfApi */

jQuery(($) => {
	const checker = EmailAuthPlugin.instance.makeChecker(
		'spf',
		'SPF',
		() => `${eauthSpfApi.check}/${EmailAuthPlugin.instance.bounceDomain}`,
		() => {
			if (EmailAuthPlugin.instance.bounceDomain === null) {
				return {
					pass: null,
					reason: 'Unknown bounce address domain.',
				};
			}
		},
		(res) => {
			const out = [
				$('<div>').append(
					'Result code: ',
					$('<code>').text(res.code),
					' for server ',
					$('<code>').text(res.server_ip),
					' ',
					$('<button>')
						.attr('type', 'button')
						.text('Configure Server IP')
						.addClass('button-link')
						.on('click', () =>
							$('#eauth-spf-set-ip-dialog')[0].showModal()
						)
				),
				EmailAuthPlugin.createCommentList(
					res.code_reasons,
					'Details',
					'h4'
				),
			];

			out.push($('<h3>').text('Validity Check'));

			if (res.cur_rec) {
				out.push(
					$('<div>').append(
						'Current record: ',
						$('<code>').text(res.cur_rec)
					)
				);

				if (!res.cur_validity.length) {
					res.cur_validity.push({
						level: 'pass',
						desc: 'Current record is schematically valid.',
					});
				}

				out.push(
					EmailAuthPlugin.createCommentList(
						res.cur_validity,
						'Issues',
						'h4'
					)
				);
			} else {
				out.push(
					$('<div>').append(
						`${EmailAuthPlugin.EMOJIS.error} No syntactically valid record found.`
					)
				);
			}

			if (res.rec_dns) {
				out.push($('<h3>').text('Suggested DNS Record'));

				out.push(
					EmailAuthPlugin.createTxtRecord(
						EmailAuthPlugin.instance.bounceDomain,
						res.rec_dns
					),
					EmailAuthPlugin.createCommentList(
						res.rec_reasons,
						'Reasons',
						'h4'
					)
				);
			}

			return out;
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
			type: 'Bounce Address',
			link: '#bounce-address',
		},
		{
			get: () => EmailAuthPlugin.instance.bounceDomain,
		}
	);

	checker.boundCheck();
	EmailAuthPlugin.instance.addEventListener(
		'bouncedomainchange',
		checker.boundCheck
	);

	$('#eauth-spf-set-ip').on('click', async (e) => {
		e.preventDefault();

		const mode = $('[name="eauth_spf_server_ip"]:checked').val().trim();
		const custom = $('[name="eauth_spf_server_ip_custom"]').val().trim();

		const res = await EmailAuthPlugin.request(
			`${eauthSpfApi.setIp}`,
			'POST',
			{
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ mode, custom }),
			}
		);

		if (!res.ok) {
			return;
		}

		const json = await res.json();

		const escapedMode = CSS.escape(json.mode);
		$('[name="eauth_spf_server_ip"][value="' + escapedMode + '"]').prop(
			'checked',
			true
		);

		$('[name="eauth_spf_server_ip_custom"]').val(json.custom || '');

		$('#eauth-spf-set-ip-dialog')[0].close();
		checker.boundCheck();
	});

	$('#eauth-spf-set-ip-close').on('click', (e) => {
		e.preventDefault();
		$('#eauth-spf-set-ip-dialog')[0].close();
	});
});
