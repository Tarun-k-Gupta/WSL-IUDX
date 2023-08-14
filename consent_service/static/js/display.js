var template = `
    <table bgcolor="#FFFFFF">
        <tr>
            <th>apd_name</th>
            <th>modality</th>
            <th>predicate</th>
            <th>condition</th>
            <th>condition_type</th>
            <th>action</th>
            <th>RegulationSource</th>
        </tr>

        {{#each response}}
            <tr>
                <td>{{apd_name}}</td>
                <td>{{modality}}</td>
                <td>{{predicate}}</td>
                <td>{{condition}}</td>
                <td>{{condition_type}}</td>
                <td>{{modality}}</td>
                <td>{{action}}</td>
                <td>{{RegulationSource}}</td>
            </tr>
        {{/each}}
    </table>
`;
pm.visualizer.set(template, {
    // Pass the response body parsed as JSON as `data`
    response: pm.response.json()
});
// {\"model\": \"consent_service.policybigtable\", \"pk\": 1, \"fields\": {\"apd_name\": \"IIITB\", \"modality\": \"O\", \"predicate\": \"request:has_purpose_code;resource:has_tag(\\\"private_research_data\\\")\", \"condition\": \"role==\\\"professor\\\"\", \"condition_type\": \"pre\", \"action\": \"\", \"RegulationSource\": null}}