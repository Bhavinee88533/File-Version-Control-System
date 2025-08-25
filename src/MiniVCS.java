import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * MiniVCS — a tiny, single-file, console version control system (like a mini Git).
 *
 * Features:
 *  - init: create repo in .minivcs
 *  - add <file|dir|.>: track files
 *  - commit -m "message": snapshot tracked files into a new version
 *  - log: list version history (current branch)
 *  - branches: list branches
 *  - branch <name>: create a new branch at current HEAD
 *  - checkout <branch>: switch to branch and restore its HEAD files
 *  - rollback <commitHash>: move HEAD to a previous commit and restore files
 *  - status: show tracked files & simple change hints
 *
 * Implementation highlights:
 *  - File I/O & Java serialization to persist repository state in .minivcs/repo.ser
 *  - SHA-256 hashing for object content addressing (.minivcs/objects/<hash>)
 *  - Collections (Maps) for branches -> head commit, file -> blob hash, etc.
 *  - Minimal, human-friendly CLI; no external libs.
 */
public class MiniVCS {
    // ---------- Public entry ----------
    public static void main(String[] args) {
        try {
            CLI.run(args);
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    // ---------- CLI ----------
    static class CLI {
        static void run(String[] args) throws Exception {
            if (args.length == 0) {
                printHelp();
                return;
            }
            String cmd = args[0];

            switch (cmd) {
                case "init":
                    Repository.init();
                    System.out.println("Initialized empty MiniVCS repository in " + RepoFiles.repoDir().toAbsolutePath());
                    break;
                case "add": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    if (args.length < 2) die("usage: add <file|dir|.>");
                    int added = repo.addPath(args[1]);
                    repo.save();
                    System.out.println("Added/updated " + added + " path(s) to tracking.");
                    break;
                }
                case "commit": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    String msg = parseCommitMessage(args);
                    if (msg == null || msg.isEmpty()) die("usage: commit -m \"message\"");
                    String hash = repo.commit(msg);
                    repo.save();
                    System.out.println("Committed as " + hash + " on branch " + repo.currentBranch + ".");
                    break;
                }
                case "log": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    repo.printLog();
                    break;
                }
                case "status": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    repo.printStatus();
                    break;
                }
                case "branches": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    repo.printBranches();
                    break;
                }
                case "branch": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    if (args.length < 2) die("usage: branch <name>");
                    repo.createBranch(args[1]);
                    repo.save();
                    System.out.println("Created branch '" + args[1] + "' at " + repo.branches.get(args[1]) + ".");
                    break;
                }
                case "checkout": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    if (args.length < 2) die("usage: checkout <branch>");
                    repo.checkoutBranch(args[1]);
                    repo.save();
                    System.out.println("Switched to branch '" + repo.currentBranch + "' at " + repo.getHead() + ".");
                    break;
                }
                case "rollback": {
                    Repository repo = Repository.load();
                    ensureRepo(repo);
                    if (args.length < 2) die("usage: rollback <commitHashPrefix>");
                    String resolved = repo.resolveCommitPrefix(args[1]);
                    if (resolved == null) die("commit not found: " + args[1]);
                    repo.rollback(resolved);
                    repo.save();
                    System.out.println("Rolled back branch '" + repo.currentBranch + "' to " + resolved + ".");
                    break;
                }
                case "help":
                default:
                    printHelp();
            }
        }

        static void ensureRepo(Repository repo) {
            if (repo == null) die("Not a MiniVCS repository (run 'init' first).");
        }

        static String parseCommitMessage(String[] args) {
            for (int i = 1; i < args.length; i++) {
                if ("-m".equals(args[i]) && i + 1 < args.length) {
                    return args[i + 1];
                }
            }
            return null;
        }

        static void printHelp() {
            System.out.println("MiniVCS — commands:\n" +
                    "  init\n" +
                    "  add <file|dir|.>\n" +
                    "  commit -m \"message\"\n" +
                    "  log\n" +
                    "  status\n" +
                    "  branches\n" +
                    "  branch <name>\n" +
                    "  checkout <branch>\n" +
                    "  rollback <commitHashPrefix>\n" +
                    "  help\n");
        }

        static void die(String msg) { throw new RuntimeException(msg); }
    }

    // ---------- Repository & core models ----------
    static class Repository implements Serializable {
        private static final long serialVersionUID = 1L;

        Map<String, String> branches = new LinkedHashMap<>(); // branch -> head commit hash
        String currentBranch = "main";
        Set<String> tracked = new TreeSet<>(); // relative file paths

        // ----- lifecycle -----
        static void init() throws Exception {
            Path repoDir = RepoFiles.repoDir();
            if (Files.exists(repoDir)) throw new RuntimeException("Repository already exists here.");
            Files.createDirectories(RepoFiles.objectsDir());
            Files.createDirectories(RepoFiles.commitsDir());

            Repository repo = new Repository();
            // create initial empty commit
            Commit root = Commit.create("Initial commit", null, Collections.emptyMap());
            root.persist();
            repo.branches.put("main", root.hash);
            repo.currentBranch = "main";
            repo.save();
        }

        static Repository load() throws Exception {
            Path p = RepoFiles.repoSer();
            if (!Files.exists(p)) return null;
            try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(p))) {
                return (Repository) ois.readObject();
            }
        }

        void save() throws Exception {
            Files.createDirectories(RepoFiles.repoDir());
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(RepoFiles.repoSer()))) {
                oos.writeObject(this);
            }
        }

        // ----- operations -----
        int addPath(String path) throws IOException {
            Path base = Paths.get("").toAbsolutePath();
            Path p = base.resolve(path).normalize();
            int[] count = {0};
            if (!Files.exists(p)) throw new RuntimeException("path not found: " + path);
            if (Files.isDirectory(p)) {
                Files.walk(p)
                        .filter(Files::isRegularFile)
                        .filter(f -> !f.toString().contains(File.separator + ".minivcs" + File.separator))
                        .forEach(f -> { tracked.add(base.relativize(f).toString().replace('\\', '/')); count[0]++; });
            } else {
                tracked.add(base.relativize(p).toString().replace('\\', '/')); count[0]++;
            }
            return count[0];
        }

        String commit(String message) throws Exception {
            // snapshot tracked files -> blob hashes
            Map<String, String> fileToBlob = new TreeMap<>();
            for (String rel : tracked) {
                Path p = Paths.get(rel);
                if (!Files.exists(p)) continue; // skip missing files
                byte[] content = Files.readAllBytes(p);
                String blobHash = Hash.sha256Hex((rel + "\0").getBytes(), content);
                Path blobPath = RepoFiles.objectsDir().resolve(blobHash);
                if (!Files.exists(blobPath)) Files.write(blobPath, content);
                fileToBlob.put(rel, blobHash);
            }
            Commit parent = getHeadCommit();
            Commit c = Commit.create(message, parent == null ? null : parent.hash, fileToBlob);
            c.persist();
            branches.put(currentBranch, c.hash);
            return c.hash;
        }

        void printLog() throws Exception {
            String head = getHead();
            if (head == null) { System.out.println("(no commits)"); return; }
            Commit c = Commit.load(head);
            while (c != null) {
                System.out.println("commit " + c.hash);
                System.out.println("Date:   " + c.dateString());
                System.out.println("Branch: " + currentBranch);
                System.out.println("    " + c.message);
                System.out.println();
                c = c.parentHash == null ? null : Commit.load(c.parentHash);
            }
        }

        void printStatus() throws Exception {
            System.out.println("On branch " + currentBranch);
            System.out.println("Tracked (" + tracked.size() + "): ");
            for (String t : tracked) System.out.println("  " + t);
            System.out.println();
            // very light-weight diff: show files whose current content hash differs from HEAD
            Commit head = getHeadCommit();
            Map<String, String> headMap = head == null ? Collections.emptyMap() : head.fileToBlob;
            List<String> modified = new ArrayList<>();
            List<String> untracked = new ArrayList<>();
            Set<String> wd = WorkingDir.listAll();
            for (String f : wd) {
                if (!tracked.contains(f)) { untracked.add(f); continue; }
                String nowHash = Hash.sha256Hex((f + "\0").getBytes(), Files.readAllBytes(Paths.get(f)));
                String oldHash = headMap.get(f);
                if (oldHash == null || !oldHash.equals(nowHash)) modified.add(f);
            }
            if (!modified.isEmpty()) {
                System.out.println("Changes not staged for commit:");
                for (String m : modified) System.out.println("  " + m);
                System.out.println();
            }
            if (!untracked.isEmpty()) {
                System.out.println("Untracked files (use 'add <file>' to track):");
                for (String u : untracked) System.out.println("  " + u);
            }
        }

        void printBranches() {
            System.out.println("Branches:");
            for (String b : branches.keySet()) {
                String marker = b.equals(currentBranch) ? "*" : " ";
                System.out.println(" " + marker + " " + b + "\t" + abbrev(branches.get(b)));
            }
        }

        void createBranch(String name) {
            if (branches.containsKey(name)) throw new RuntimeException("branch exists: " + name);
            String head = getHead();
            branches.put(name, head);
        }

        void checkoutBranch(String name) throws Exception {
            if (!branches.containsKey(name)) throw new RuntimeException("no such branch: " + name);
            currentBranch = name;
            restoreCommit(getHead());
        }

        void rollback(String commitHash) throws Exception {
            Commit c = Commit.load(commitHash);
            if (c == null) throw new RuntimeException("commit not found: " + commitHash);
            branches.put(currentBranch, c.hash);
            restoreCommit(c.hash);
        }

        String resolveCommitPrefix(String prefix) throws Exception {
            // naive scan of commits dir for a matching prefix
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(RepoFiles.commitsDir())) {
                String found = null;
                for (Path p : ds) {
                    String name = p.getFileName().toString();
                    if (name.startsWith(prefix)) {
                        if (found != null) throw new RuntimeException("ambiguous prefix; use more characters");
                        found = name;
                    }
                }
                return found;
            }
        }

        String getHead() { return branches.get(currentBranch); }
        Commit getHeadCommit() throws Exception { String h = getHead(); return h == null ? null : Commit.load(h); }

        void restoreCommit(String hash) throws Exception {
            Commit c = Commit.load(hash);
            if (c == null) throw new RuntimeException("commit not found: " + hash);
            // write files from commit; also remove tracked files that are absent in commit
            Set<String> keep = c.fileToBlob.keySet();
            // Remove files that are tracked but not in commit
            for (String t : new ArrayList<>(tracked)) {
                if (!keep.contains(t)) {
                    Path p = Paths.get(t);
                    if (Files.exists(p)) Files.delete(p);
                }
            }
            // Write/overwrite files from commit
            for (Map.Entry<String,String> e : c.fileToBlob.entrySet()) {
                String rel = e.getKey();
                String blob = e.getValue();
                Path dest = Paths.get(rel);
                Files.createDirectories(dest.getParent() == null ? Paths.get("") : dest.getParent());
                byte[] content = Files.readAllBytes(RepoFiles.objectsDir().resolve(blob));
                Files.write(dest, content);
            }
        }

        static String abbrev(String hash) { return hash == null ? "-" : (hash.length() <= 8 ? hash : hash.substring(0, 8)); }
    }

    static class Commit implements Serializable {
        private static final long serialVersionUID = 1L;
        final String hash;
        final String parentHash;
        final String message;
        final long timestamp;
        final Map<String, String> fileToBlob; // rel path -> blob hash

        private Commit(String hash, String parentHash, String message, long timestamp, Map<String,String> fileToBlob) {
            this.hash = hash; this.parentHash = parentHash; this.message = message; this.timestamp = timestamp; this.fileToBlob = fileToBlob;
        }

        static Commit create(String message, String parentHash, Map<String,String> fileToBlob) throws Exception {
            long ts = System.currentTimeMillis();
            // Hash includes parent, message, ts, and file->blob pairs
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write((parentHash == null ? "" : parentHash).getBytes());
            bos.write('\n');
            bos.write(message.getBytes());
            bos.write('\n');
            bos.write(Long.toString(ts).getBytes());
            bos.write('\n');
            for (Map.Entry<String,String> e : fileToBlob.entrySet()) {
                bos.write(e.getKey().getBytes()); bos.write('='); bos.write(e.getValue().getBytes()); bos.write('\n');
            }
            String hash = Hash.sha256Hex(bos.toByteArray());
            return new Commit(hash, parentHash, message, ts, new TreeMap<>(fileToBlob));
        }

        String dateString() {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(timestamp));
        }

        void persist() throws Exception {
            Path p = RepoFiles.commitsDir().resolve(hash);
            try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(p))) {
                oos.writeObject(this);
            }
        }

        static Commit load(String hash) throws Exception {
            Path p = RepoFiles.commitsDir().resolve(hash);
            if (!Files.exists(p)) return null;
            try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(p))) {
                return (Commit) ois.readObject();
            }
        }
    }

    // ---------- Utilities ----------
    static class RepoFiles {
        static Path repoDir() { return Paths.get(".minivcs"); }
        static Path repoSer() { return repoDir().resolve("repo.ser"); }
        static Path objectsDir() { return repoDir().resolve("objects"); }
        static Path commitsDir() { return repoDir().resolve("commits"); }
    }

    static class WorkingDir {
        static Set<String> listAll() throws IOException {
            Set<String> out = new TreeSet<>();
            Path base = Paths.get("").toAbsolutePath();
            Files.walk(base)
                .filter(Files::isRegularFile)
                .filter(p -> !p.toString().contains(File.separator + ".minivcs" + File.separator))
                .forEach(p -> out.add(base.relativize(p).toString().replace('\\', '/')));
            return out;
        }
    }

    static class Hash {
        static String sha256Hex(byte[]... chunks) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                for (byte[] c : chunks) md.update(c);
                byte[] d = md.digest();
                StringBuilder sb = new StringBuilder();
                for (byte b : d) sb.append(String.format("%02x", b));
                return sb.toString();
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }
}
