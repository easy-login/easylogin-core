$(document).ready(function() {
    selectedForm = $('#id_form_link');
    $('#id_api_name').change(function() {
        var apiName = $('#id_api_name').val();
        console.log(apiName);
        selectedForm.hide();
        if (apiName === 'link_user') {
            selectedForm = $('#id_form_link');
        } else if (apiName === 'unlink_user') {
            selectedForm = $('#id_form_unlink');
        } else if (apiName === 'diassociate') {
            selectedForm = $('#id_form_disassociate');
        } else if (apiName == 'profile') {
            selectedForm = $('#id_form_profile');
        }
        selectedForm.show();
    });

    function updateResult(response) {
        var json = JSON.stringify(response, null, 2);
        $('#result').html(json);
        $('#result').each(function(i, element) {
            hljs.highlightBlock(element);
        });
    }

    function linkUser() {
        $.ajax({
            url: '/api/link',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_link').val(),
                'social_id': $('#id_social_id_link').val(),
                'response_type': 'json'
            }
        }).done(updateResult);
    }

    function unlinkUser() {
        $.ajax({
            url: '/api/unlink',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_unlink').val(),
                'social_id': $('#id_social_id_unlink').val(),
                'response_type': 'json'
            }
        }).done(updateResult);
    }

    function diassociate() {
        var body = {
            'providers': $('#id_providers_disassociate').val(),
            'response_type': 'json'
        };
        if ($('#id_user_id_disassociate').val().length > 0) {
            body.user_id = $('#id_user_id_disassociate').val();
        } else {
            body.social_id = $('#id_social_id_disassociate').val();
        }
        $.ajax({
            url: '/api/disassociate',
            type: 'POST',
            dataType: 'json',
            data: body
        }).done(updateResult);
    }

    function getProfile() {
        var body = {};
        if ($('#id_user_id_profile').val().length > 0) {
            body.user_id = $('#id_user_id_profile').val();
        } else {
            body.social_id = $('#id_social_id_profile').val();
        }
        $.ajax({
            url: '/api/profile',
            type: 'POST',
            dataType: 'json',
            data: body
        }).done(updateResult);
    }

    $('#btn_submit').click(function() {
        var apiName = $('#id_api_name').val();
        console.log('Call API: ' + apiName);
        if (apiName === 'link_user') {
            linkUser();
        } else if (apiName === 'unlink_user') {
            unlinkUser();
        } else if (apiName === 'diassociate') {
            diassociate();
        } else if (apiName == 'profile') {
            getProfile();
        }
    });
});