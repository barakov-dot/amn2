from app.services.integration_status import build_client_compatibility_boundary


def test_phase7_boundary_blocks_phase8_until_android_real_device_acceptance():
    boundary = build_client_compatibility_boundary()

    assert boundary["android"]["supported_path"] == "AmneziaWG Android"
    assert boundary["android"]["acceptance_status"] == "pending_real_device_acceptance"
    assert boundary["android"]["release_primary_allowed"] is False
    assert (
        boundary["phase8_mobile_gate_status"]
        == "blocked_android_real_device_acceptance_pending"
    )
    assert boundary["qr_release_primary_allowed"] is False
    assert boundary["vpn_import_link_release_primary_allowed"] is False
    assert boundary["desktop"]["windows_observation_status"] == "operator_observed_passed"
