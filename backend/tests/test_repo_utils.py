"""
Tests for app.utils.repo_utils.parse_repository_url.

Verifies both backward-compatible behavior (owner/repo/base_url/project_path/server_url)
and the new URL-ref parsing (ref/ref_type/path_in_repo/canonical_url) that lets
DeepAudit correctly honor tag/commit/blob URLs passed by users.
"""

import pytest

from app.utils.repo_utils import parse_repository_url, extract_ref_from_url


# ---------------------------------------------------------------------------
# Backward compatibility: existing callers rely on these exact fields.
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    def test_github_root_url_yields_original_fields(self):
        info = parse_repository_url("https://github.com/pallets/flask", "github")
        assert info["owner"] == "pallets"
        assert info["repo"] == "flask"
        assert info["base_url"] == "https://api.github.com"
        assert info["server_url"] == "https://github.com"
        assert info["project_path"] == "pallets/flask"

    def test_github_root_with_git_suffix(self):
        info = parse_repository_url("https://github.com/pallets/flask.git", "github")
        assert info["owner"] == "pallets"
        assert info["repo"] == "flask"
        assert info["canonical_url"] == "https://github.com/pallets/flask"

    def test_gitlab_root_url_with_subgroup(self):
        info = parse_repository_url("https://gitlab.com/group/sub/proj", "gitlab")
        assert info["repo"] == "proj"
        assert info["owner"] == "group/sub"
        assert info["project_path"] == "group/sub/proj"
        assert info["base_url"] == "https://gitlab.com/api/v4"

    def test_gitea_root_url(self):
        info = parse_repository_url("https://gitea.example.com/foo/bar", "gitea")
        assert info["owner"] == "foo"
        assert info["repo"] == "bar"
        assert info["base_url"] == "https://gitea.example.com/api/v1"

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            parse_repository_url("git://github.com/x/y", "github")

    def test_missing_owner_or_repo_raises(self):
        with pytest.raises(ValueError):
            parse_repository_url("https://github.com/only-owner", "github")

    def test_empty_url_raises(self):
        with pytest.raises(ValueError):
            parse_repository_url("", "github")

    def test_unsupported_repo_type_raises(self):
        with pytest.raises(ValueError):
            parse_repository_url("https://x.com/a/b", "bitbucket")


# ---------------------------------------------------------------------------
# GitHub: /tree, /blob, /commit, /releases/tag, /commits, /raw
# ---------------------------------------------------------------------------

class TestGithubRefExtraction:
    def test_tree_with_tag(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/tree/2.0.0", "github"
        )
        assert info["owner"] == "pallets"
        assert info["repo"] == "flask"
        assert info["ref"] == "2.0.0"
        assert info["ref_type"] == "ref"  # can't disambiguate tag vs branch from URL alone
        assert info["path_in_repo"] is None
        assert info["canonical_url"] == "https://github.com/pallets/flask"

    def test_tree_with_branch_slash_path(self):
        # GitHub 允许 /tree/<ref>/<sub/dir>，ref 只是第一段
        info = parse_repository_url(
            "https://github.com/pallets/flask/tree/main/src/flask", "github"
        )
        assert info["ref"] == "main"
        assert info["path_in_repo"] == "src/flask"

    def test_blob_with_file(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/blob/2.0.0/README.rst", "github"
        )
        assert info["ref"] == "2.0.0"
        assert info["path_in_repo"] == "README.rst"

    def test_commit_url(self):
        sha = "a" * 40
        info = parse_repository_url(
            f"https://github.com/pallets/flask/commit/{sha}", "github"
        )
        assert info["ref"] == sha
        assert info["ref_type"] == "commit"

    def test_tree_with_short_commit_sha_detected(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/tree/deadbeef", "github"
        )
        assert info["ref"] == "deadbeef"
        assert info["ref_type"] == "commit"

    def test_releases_tag(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/releases/tag/2.0.0", "github"
        )
        assert info["ref"] == "2.0.0"
        assert info["ref_type"] == "tag"

    def test_commits_variant(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/commits/main", "github"
        )
        assert info["ref"] == "main"

    def test_url_with_git_suffix_still_parses_ref(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask.git", "github"
        )
        assert info["ref"] is None
        assert info["repo"] == "flask"

    def test_enterprise_github(self):
        info = parse_repository_url(
            "https://ghe.corp/team/proj/tree/release-1.2", "github"
        )
        assert info["owner"] == "team"
        assert info["repo"] == "proj"
        assert info["ref"] == "release-1.2"
        assert info["base_url"] == "https://ghe.corp/api/v3"

    def test_trailing_slash(self):
        info = parse_repository_url(
            "https://github.com/pallets/flask/tree/2.0.0/", "github"
        )
        assert info["ref"] == "2.0.0"
        assert info["path_in_repo"] is None


# ---------------------------------------------------------------------------
# GitLab: with and without the "-" separator; subgroups
# ---------------------------------------------------------------------------

class TestGitlabRefExtraction:
    def test_new_style_tree_with_dash(self):
        info = parse_repository_url(
            "https://gitlab.com/group/proj/-/tree/v1.2.3", "gitlab"
        )
        assert info["project_path"] == "group/proj"
        assert info["owner"] == "group"
        assert info["repo"] == "proj"
        assert info["ref"] == "v1.2.3"

    def test_new_style_subgroup(self):
        info = parse_repository_url(
            "https://gitlab.com/g/sub/proj/-/blob/main/README.md", "gitlab"
        )
        assert info["project_path"] == "g/sub/proj"
        assert info["owner"] == "g/sub"
        assert info["repo"] == "proj"
        assert info["ref"] == "main"
        assert info["path_in_repo"] == "README.md"

    def test_old_style_no_dash(self):
        info = parse_repository_url(
            "https://gitlab.com/group/proj/tree/main", "gitlab"
        )
        assert info["project_path"] == "group/proj"
        assert info["ref"] == "main"

    def test_tags_variant(self):
        info = parse_repository_url(
            "https://gitlab.com/group/proj/-/tags/v1.0", "gitlab"
        )
        assert info["ref"] == "v1.0"
        assert info["ref_type"] == "tag"

    def test_commit_sha(self):
        sha = "abcdef1234"
        info = parse_repository_url(
            f"https://gitlab.com/group/proj/-/commit/{sha}", "gitlab"
        )
        assert info["ref"] == sha
        assert info["ref_type"] == "commit"

    def test_root_only(self):
        info = parse_repository_url("https://gitlab.com/group/proj", "gitlab")
        assert info["ref"] is None
        assert info["project_path"] == "group/proj"


# ---------------------------------------------------------------------------
# Gitea: /src/branch, /src/tag, /src/commit, /commit
# ---------------------------------------------------------------------------

class TestGiteaRefExtraction:
    def test_src_branch(self):
        info = parse_repository_url(
            "https://gitea.example.com/foo/bar/src/branch/dev", "gitea"
        )
        assert info["ref"] == "dev"
        assert info["ref_type"] == "ref"

    def test_src_tag(self):
        info = parse_repository_url(
            "https://gitea.example.com/foo/bar/src/tag/v1.0", "gitea"
        )
        assert info["ref"] == "v1.0"
        assert info["ref_type"] == "tag"

    def test_src_commit(self):
        sha = "1234567"
        info = parse_repository_url(
            f"https://gitea.example.com/foo/bar/src/commit/{sha}", "gitea"
        )
        assert info["ref"] == sha
        assert info["ref_type"] == "commit"

    def test_raw_branch_with_file(self):
        info = parse_repository_url(
            "https://gitea.example.com/foo/bar/raw/branch/main/README.md", "gitea"
        )
        assert info["ref"] == "main"
        assert info["path_in_repo"] == "README.md"

    def test_bare_commit_path(self):
        sha = "deadbee"
        info = parse_repository_url(
            f"https://gitea.example.com/foo/bar/commit/{sha}", "gitea"
        )
        assert info["ref"] == sha
        assert info["ref_type"] == "commit"


# ---------------------------------------------------------------------------
# extract_ref_from_url convenience helper
# ---------------------------------------------------------------------------

class TestExtractRefHelper:
    def test_returns_ref_tuple(self):
        ref, kind = extract_ref_from_url(
            "https://github.com/pallets/flask/tree/2.0.0", "github"
        )
        assert ref == "2.0.0"
        assert kind == "ref"

    def test_returns_none_for_invalid(self):
        ref, kind = extract_ref_from_url("not-a-url", "github")
        assert ref is None
        assert kind is None

    def test_returns_none_for_root(self):
        ref, kind = extract_ref_from_url(
            "https://github.com/pallets/flask", "github"
        )
        assert ref is None
        assert kind is None
