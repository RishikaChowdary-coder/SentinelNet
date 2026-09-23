import random
import time


def generate_flow(flow_type="normal"):
    """
    Generate a safe synthetic network-flow record.
    No real network traffic is generated.
    """

    if flow_type == "normal":

        packet_count = random.randint(20, 300)
        byte_count = random.randint(2000, 300000)
        flow_duration = random.uniform(1.0, 30.0)

        protocol = random.choice([
            "TCP",
            "UDP",
            "ICMP"
        ])

        destination_port = random.choice([
            53,
            80,
            443,
            22,
            123
        ])


    elif flow_type == "syn":

        packet_count = random.randint(
            800,
            3000
        )

        byte_count = random.randint(
            20000,
            150000
        )

        flow_duration = random.uniform(
            0.1,
            2.0
        )

        protocol = "TCP"

        destination_port = random.choice([
            80,
            443,
            8080
        ])


    elif flow_type == "c2":

        packet_count = random.randint(
            10,
            80
        )

        byte_count = random.randint(
            1000,
            30000
        )

        flow_duration = random.uniform(
            20.0,
            60.0
        )

        protocol = "TCP"

        destination_port = random.choice([
            443,
            8443
        ])


    elif flow_type == "dga":

        packet_count = random.randint(
            10,
            100
        )

        byte_count = random.randint(
            500,
            15000
        )

        flow_duration = random.uniform(
            0.2,
            5.0
        )

        protocol = "UDP"

        destination_port = 53


    elif flow_type == "anomaly":

        packet_count = random.randint(
            400,
            1200
        )

        byte_count = random.randint(
            500000,
            2000000
        )

        flow_duration = random.uniform(
            0.5,
            8.0
        )

        protocol = random.choice([
            "TCP",
            "UDP"
        ])

        destination_port = random.randint(
            1000,
            65000
        )


    else:

        return generate_flow(
            "normal"
        )


    packet_rate = (
        packet_count /
        max(flow_duration, 0.01)
    )

    byte_rate = (
        byte_count /
        max(flow_duration, 0.01)
    )

    average_packet_size = (
        byte_count /
        max(packet_count, 1)
    )


    return {

        "timestamp": time.time(),

        "protocol": protocol,

        "source_port":
            random.randint(
                1024,
                65535
            ),

        "destination_port":
            destination_port,

        "packet_count":
            packet_count,

        "byte_count":
            byte_count,

        "flow_duration":
            round(
                flow_duration,
                3
            ),

        "packet_rate":
            round(
                packet_rate,
                2
            ),

        "byte_rate":
            round(
                byte_rate,
                2
            ),

        "average_packet_size":
            round(
                average_packet_size,
                2
            )

    }


def generate_dataset(
    number_of_flows=100
):

    flow_types = [

        "normal",
        "normal",
        "normal",
        "normal",

        "syn",
        "c2",
        "dga",
        "anomaly"

    ]

    dataset = []


    for _ in range(
        number_of_flows
    ):

        flow_type = random.choice(
            flow_types
        )

        flow = generate_flow(
            flow_type
        )

        flow["flow_type"] = (
            flow_type
        )

        dataset.append(
            flow
        )


    return dataset


if __name__ == "__main__":

    flows = generate_dataset(
        10
    )


    for flow in flows:

        print(flow)