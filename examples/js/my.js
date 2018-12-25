$(document).ready(function() {
    $('#btn_submit_link').click(function() {
        console.log('btn_submit_link click');
        $.ajax({
            url: '/api/link',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_link').val(),
                'social_id': $('#id_social_id_link').val(),
                'response_type': 'json'
            }
        }).done(function(response) {
            var json = JSON.stringify(response, null, 2);
            $('#result_link').html(json);
            $('#result_link').each(function(i, element) {
                hljs.highlightBlock(element);
            });
        });
    });

    $('#btn_submit_unlink').click(function() {
        console.log('btn_submit_unlink click');
        $.ajax({
            url: '/api/unlink',
            type: 'POST',
            dataType: 'json',
            data: {
                'user_id': $('#id_user_id_unlink').val(),
                'social_id': $('#id_social_id_unlink').val(),
                'response_type': 'json'
            }
        }).done(function(response) {
            var json = JSON.stringify(response, null, 2);
            $('#result_unlink').html(json);
            $('#result_unlink').each(function(i, element) {
                hljs.highlightBlock(element);
            });
        });
    });

    $('#btn_submit_disassociate').click(function() {
        console.log('btn_submit_disassociate click');
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
        }).done(function(response) {
            console.log('response ' + response.status_code);
            var json = JSON.stringify(response, null, 2);
            $('#result_disassociate').html(json);
            $('#result_disassociate').each(function(i, element) {
                hljs.highlightBlock(element);
            });
        });
    });

    $('#btn_submit_profile').click(function() {
        console.log('btn_submit_profile click');
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
        }).done(function(response) {
            var json = JSON.stringify(response, null, 2);
            $('#result_profile').html(json);
            $('#result_profile').each(function(i, element) {
                hljs.highlightBlock(element);
            });
        });
    });
});