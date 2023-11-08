
// DO NOT EDIT THIS BLOCK BELOW=== Parameters starts ===
// PLEASE DO NOT EDIT THIS FILE

import com.cloudbees.flowpdf.StepParameters

class CommitWithSignatureParameters {
    /**
    * Label: Repository path, type: entry
    */
    String repoPath
    /**
    * Label: Branch name, type: entry
    */
    String branch
    /**
    * Label: Files to add, type: textarea
    */
    String files
    /**
    * Label: Push?, type: checkbox
    */
    boolean push

    static CommitWithSignatureParameters initParameters(StepParameters sp) {
        CommitWithSignatureParameters parameters = new CommitWithSignatureParameters()

        def repoPath = sp.getRequiredParameter('repoPath').value
        parameters.repoPath = repoPath

        def branch = sp.getRequiredParameter('branch').value
        parameters.branch = branch

        def files = sp.getRequiredParameter('files').value
        parameters.files = files

        def push = sp.getParameter('push').value == "true"
        parameters.push = push

        return parameters
    }
}
// DO NOT EDIT THIS BLOCK ABOVE ^^^=== Parameters ends, checksum: 51734b8ffb299cb40bdbf58edb71e4a4 ===
