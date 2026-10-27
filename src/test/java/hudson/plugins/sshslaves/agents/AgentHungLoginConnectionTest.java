package hudson.plugins.sshslaves.agents;

import static hudson.plugins.sshslaves.tags.TestTags.AGENT_SSH_TEST;
import static hudson.plugins.sshslaves.tags.TestTags.SSH_KEY_AUTHENTICATION_TEST;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.Node;
import hudson.plugins.sshslaves.Messages;
import hudson.plugins.sshslaves.SSHLauncher;
import java.io.IOException;
import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;

/**
 * The remote authenticates and then never finishes the command the launcher runs to check the login for junk, so the
 * launch must give up on its own, release the agent and leave no stale connection for the next attempt.
 */
@Tag(AGENT_SSH_TEST)
@Tag(SSH_KEY_AUTHENTICATION_TEST)
class AgentHungLoginConnectionTest extends AgentConnectionBaseTest {
    private static final String SSH_AGENT_NAME = "ssh-agent-rsa";
    private static final String SSH_KEY_PATH = "ssh/rsa-key";
    private static final String SSH_KEY_PUB_PATH = "ssh/rsa-key.pub";

    @Container
    private static final GenericContainer<?> agentContainer = new GenericContainer<>(new ImageFromDockerfile(
                            SSH_AGENT_NAME + "-hung-login", false)
                    .withFileFromClasspath(
                            SSH_AUTHORIZED_KEYS,
                            AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_AUTHORIZED_KEYS)
                    .withFileFromClasspath(
                            SSH_KEY_PATH, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_KEY_PATH)
                    .withFileFromClasspath(
                            SSH_KEY_PUB_PATH, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_KEY_PUB_PATH)
                    .withFileFromClasspath(
                            SSH_SSHD_CONFIG, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + SSH_SSHD_CONFIG)
                    .withFileFromClasspath(DOCKERFILE, AGENTS_RESOURCES_PATH + "/" + SSH_AGENT_NAME + "/" + DOCKERFILE))
            .withExposedPorts(SSH_PORT);

    @Override
    protected void customizeLauncher(SSHLauncher launcher) {
        launcher.setLaunchTimeoutSeconds(1);
        launcher.setMaxNumRetries(0);
        launcher.setRetryWaitTime(0);
    }

    @Override
    void connectionTests() throws IOException, InterruptedException, Descriptor.FormException {
        // ForceCommand replaces "exit 0" with a command that never closes stdout, as a stalled login does.
        agentContainer.execInContainer(
                "sh", "-c", "echo 'ForceCommand sleep 3600' >> /etc/ssh/sshd_config && pkill -HUP -o sshd");

        Node node = createPermanentAgent(
                getAgentName(),
                agentContainer.getHost(),
                agentContainer.getMappedPort(SSH_PORT),
                getAgentSshKeyPath(),
                getAgentSshKeyPassphrase());
        Computer computer = node.toComputer();

        assertTimeoutPreemptively(Duration.ofSeconds(90), () -> {
            while (computer.isConnecting() || computer.getLog().isEmpty()) {
                Thread.sleep(500);
            }
        });
        assertTrue(computer.isOffline());
        assertTrue(computer.getLog().contains(Messages.SSHLauncher_launchCanceled()), computer.getLog());

        // A second attempt must run a real launch instead of stopping at "already connected".
        assertTimeoutPreemptively(Duration.ofSeconds(90), () -> {
            computer.connect(true).get();
        });
        assertFalse(computer.getLog().contains(Messages.SSHLauncher_alreadyConnected()), computer.getLog());
    }

    @Override
    protected String getAgentName() {
        return SSH_AGENT_NAME;
    }

    @Override
    protected GenericContainer<?> getAgentContainer() {
        return agentContainer;
    }

    @Override
    protected String getAgentSshKeyPath() {
        return SSH_AGENT_NAME + "/" + SSH_KEY_PATH;
    }
}
